package plugin

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// hostListenerConfig is the subset needed for local native management calls.
// New server.* values win by presence; legacy top-level fields remain supported.
type hostListenerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	TLS  struct {
		Enable bool   `yaml:"enable"`
		Cert   string `yaml:"cert"`
	} `yaml:"tls"`
}

func parseHostListenerConfig(raw []byte) (hostListenerConfig, error) {
	var cfg hostListenerConfig
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return cfg, newHostSyncFailure("config_format", "宿主配置 YAML 无效，请检查配置格式")
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return cfg, newHostSyncFailure("config_format", "宿主配置必须是 YAML 对象")
	}
	root := document.Content[0]
	field := func(node *yaml.Node, key string) *yaml.Node {
		if node == nil {
			return nil
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				return node.Content[i+1]
			}
		}
		return nil
	}
	server := field(root, "server")
	if server != nil && server.Kind != yaml.MappingNode {
		return cfg, newHostSyncFailure("config_format", "server 必须是 YAML 对象")
	}
	for _, entry := range []struct {
		name   string
		target any
	}{{"host", &cfg.Host}, {"port", &cfg.Port}} {
		node := field(server, entry.name)
		path := "server." + entry.name
		if node == nil {
			node = field(root, entry.name)
			path = entry.name
		}
		if node == nil {
			continue
		}
		if node.Tag == "!!null" || node.Decode(entry.target) != nil {
			return cfg, newHostSyncFailure("config_format", fmt.Sprintf("宿主配置 %s 的类型或内容无效", path))
		}
	}
	legacyTLS, currentTLS := field(root, "tls"), field(server, "tls")
	if currentTLS != nil && currentTLS.Kind != yaml.MappingNode {
		return cfg, newHostSyncFailure("config_format", "宿主配置 server.tls 必须是 YAML 对象")
	}
	if legacyTLS != nil && legacyTLS.Kind != yaml.MappingNode && currentTLS == nil {
		return cfg, newHostSyncFailure("config_format", "宿主配置 tls 必须是 YAML 对象")
	}
	for _, entry := range []struct {
		name   string
		target any
	}{{"enable", &cfg.TLS.Enable}, {"cert", &cfg.TLS.Cert}} {
		node := field(currentTLS, entry.name)
		path := "server.tls." + entry.name
		if node == nil && legacyTLS != nil && legacyTLS.Kind == yaml.MappingNode {
			node = field(legacyTLS, entry.name)
			path = "tls." + entry.name
		}
		if node != nil && (node.Tag == "!!null" || node.Decode(entry.target) != nil) {
			return cfg, newHostSyncFailure("config_format", fmt.Sprintf("宿主配置 %s 的类型或内容无效", path))
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return cfg, newHostSyncFailure("config_port", "无法读取有效监听端口，请检查 server.port（旧配置为 port，范围 1–65535）")
	}
	return cfg, nil
}
