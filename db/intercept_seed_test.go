package db

import (
	"regexp"
	"testing"
)

// 内置「删除类接口路径」规则匹配的是整个 tool_input JSON 串，因此用例直接以
// JSON 形态给出，与 Interceptor 实际拿到的 subject 一致。
func TestDeleteEndpointPathPattern(t *testing.T) {
	re := regexp.MustCompile(deleteEndpointPathPattern)

	hit := []string{
		`{"command":"curl -s 'http://t.com/api/user/delete?id=1'"}`,    // GET 打删除接口
		`{"command":"curl -X POST http://t.com/admin/delete -d id=1"}`, // POST 打删除接口
		`{"command":"curl 'http://t.com/api/deleteAll'"}`,
		`{"command":"curl 'http://t.com/api/delete_user?id=1'"}`,
		`{"command":"curl 'http://t.com/api/delete-user?id=1'"}`,
		`{"url":"http://t.com/api/remove?id=1"}`,
		`{"command":"curl http://t.com/files/unlink/3"}`,
		`{"command":"curl http://t.com/api/del?id=2"}`,
		`{"command":"curl -X POST http://t/v1/erase"}`,
		`{"command":"curl http://t/admin/destroyAll"}`, // v1 的路径规则不允许后缀，这里补上
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("应命中却放行: %s", s)
		}
	}

	// 动词后必须跟分隔符，避免 /delivery、/details 这类只读路径被误拦。
	miss := []string{
		`{"command":"curl 'http://t.com/api/delivery?id=1'"}`,
		`{"command":"curl 'http://t.com/order/details'"}`,
		`{"command":"curl 'http://t.com/api/delta/sync'"}`,
		`{"command":"curl 'http://t.com/user/delegate'"}`,
		`{"command":"curl 'http://delete.example.com/'"}`, // 删除动词出现在域名而非路径
		`{"command":"curl 'http://t.com/remote/status'"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("误拦: %s", s)
		}
	}
}

func TestDefaultInterceptRulesV4Patterns(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		hits    []string
		misses  []string
	}{
		{
			name:    "aws_s3_destructive",
			pattern: awsS3DestructivePattern,
			hits: []string{
				`{"command":"aws s3 rm s3://prod-bucket/data --recursive"}`,
				`{"command":"AWS S3 RB s3://prod-bucket --force"}`,
				`{"command":"aws s3api delete-bucket --bucket prod-bucket"}`,
				`{"command":"aws s3api delete-objects --bucket prod-bucket --delete file://d.json"}`,
			},
			misses: []string{
				`{"command":"aws s3 ls s3://prod-bucket"}`,
				`{"command":"aws s3 cp s3://prod-bucket/file.txt ."}`,
				`{"command":"aws s3 rm s3://prod-bucket/single-tmp.txt"}`,
				`{"command":"aws s3 ls | grep --recursive"}`,
			},
		},
		{
			name:    "terraform_destroy",
			pattern: terraformDestroyPattern,
			hits: []string{
				`{"command":"terraform destroy -auto-approve"}`,
				`{"command":"cd infra && TERRAFORM DESTROY"}`,
			},
			misses: []string{
				`{"command":"terraform plan"}`,
				`{"command":"terraform show"}`,
			},
		},
		{
			name:    "crontab_wipe",
			pattern: crontabWipePattern,
			hits: []string{
				`{"command":"crontab -r"}`,
				`{"command":"sudo crontab -r -u www-data"}`,
			},
			misses: []string{
				`{"command":"crontab -l"}`,
				`{"command":"cat /etc/crontab"}`,
			},
		},
		{
			name:    "block_device_redirect",
			pattern: blockDeviceRedirectPattern,
			hits: []string{
				`{"command":"echo x > /dev/nvme0n1"}`,
				`{"command":"cat zero > /dev/sda"}`,
				`{"command":"printf a >/dev/vda1"}`,
				`{"command":"cat a > /dev/mapper/vg-root"}`,
			},
			misses: []string{
				`{"command":"cmd > /dev/null 2>&1"}`,
				`{"command":"ls -la /dev/nvme0n1"}`,
				`{"command":"cat /dev/shm/out.txt"}`,
			},
		},
		{
			name:    "windows_destructive",
			pattern: windowsDestructivePattern,
			hits: []string{
				`{"command":"format C: /q"}`,
				`{"command":"cmd /c del /s /q C:\\Users"}`,
				`{"command":"rd /s /q C:\\inetpub"}`,
				`{"command":"rmdir C:\\temp /s /q"}`,
				`{"command":"powershell -c Format-Volume -DriveLetter D"}`,
				`{"command":"powershell -c Clear-Disk -Number 1"}`,
				`{"command":"diskpart /s wipe.txt"}`,
			},
			misses: []string{
				`{"command":"cmd /c del C:\\temp\\probe.txt"}`,
				`{"command":"python3 -c 'print(\"{}\".format(1))'"}`,
				`{"command":"powershell -c Get-Volume"}`,
			},
		},
		{
			name:    "powershell_recursive_delete",
			pattern: powershellRecursiveDeletePattern,
			hits: []string{
				`{"command":"powershell -c Remove-Item C:\\app -Recurse -Force"}`,
				`{"command":"Remove-Item -Force -Recurse C:\\Windows\\Temp"}`,
			},
			misses: []string{
				`{"command":"powershell -c Remove-Item C:\\temp\\probe.txt -Force"}`,
				`{"command":"powershell -c Get-ChildItem -Recurse"}`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			for _, s := range tc.hits {
				if !re.MatchString(s) {
					t.Errorf("应命中却放行: %s", s)
				}
			}
			for _, s := range tc.misses {
				if re.MatchString(s) {
					t.Errorf("误拦: %s", s)
				}
			}
		})
	}
}
