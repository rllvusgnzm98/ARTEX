package agent

import (
	"fmt"
	"strings"
	"testing"
)

func TestFootprintDefaultMatchesOriginal(t *testing.T) {
	const original = `

**作业脚印红线(不可编辑)**:
1. 礼貌优先:平台会对经其记录/出口代理的目标流量按主机礼貌限速,你仍须自控并发与频率——不开超高并发洪泛,不做全端口/全字典的无脑狂扫;被限速或告警即降速、换出口、缩面,别和防护硬顶。
2. 最小触达:能被动/只读验证就不主动写;优先用一次性、可证伪的最小请求拿到判据,拿到即停,不重复捶打同一点。
3. 不留脏数据:注册/下单/支付/发帖/上传这类写操作只在必要时做,用可识别的测试标记、尽量自建可回收的测试数据,事后登记待清理;禁止批量写入、删除、改动他人数据或触发真实交易/通知。
4. 不伤他人:缓存投毒、请求走私、竞态这类可能波及其他用户的手法,只用指向自己账号/自己缓存键的无害请求自证分歧,严禁把脏响应或走私流量落到真实用户。
5. 不做破坏性或不可逆动作:DoS/资源耗尽类仅做到证明即止,绝不持续打垮目标。`
	if got := workerFootprintRulesFor(DefaultFootprint()); got != original {
		t.Fatalf("default changed:\ngot %q\nwant %q", got, original)
	}
}

func TestFootprintCombinations(t *testing.T) {
	rules := []string{footprintPace, footprintMinTouch, footprintNoDirtyData, footprintNoHarmOthers, footprintNoDestructive}
	for mask := 0; mask < 32; mask++ {
		fp := FootprintToggles{Pace: mask&1 != 0, MinTouch: mask&2 != 0, NoDirtyData: mask&4 != 0, NoHarmOthers: mask&8 != 0, NoDestructive: mask&16 != 0}
		got := workerFootprintRulesFor(fp)
		if mask == 0 {
			if got != "" {
				t.Fatalf("all off = %q", got)
			}
			continue
		}
		n := 0
		for i, rule := range rules {
			on := mask&(1<<i) != 0
			if strings.Contains(got, rule) != on {
				t.Fatalf("mask %d rule %d selection mismatch", mask, i)
			}
			if on {
				n++
				if !strings.Contains(got, fmt.Sprintf("\n%d. %s", n, rule)) {
					t.Fatalf("mask %d rule %d numbering mismatch", mask, i)
				}
			}
		}
		if strings.Count(got, "操作员已为本任务授权放宽") != boolInt(mask != 31) {
			t.Fatalf("mask %d relaxation note mismatch", mask)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestFootprintResolver(t *testing.T) {
	w := &Worker{}
	if got := w.footprintForTask(7); got != DefaultFootprint() {
		t.Fatalf("unset resolver = %+v", got)
	}
	calls := 0
	w.SetFootprintResolver(func(id int64) FootprintToggles {
		calls++
		return FootprintToggles{Pace: id == 7 && calls == 1}
	})
	if !w.footprintForTask(7).Pace || w.footprintForTask(7).Pace || w.footprintForTask(8).Pace || calls != 3 {
		t.Fatal("resolver not queried per run/task")
	}
	w.SetFootprintResolver(nil)
	if w.footprintForTask(7) != DefaultFootprint() {
		t.Fatal("nil resolver did not restore strict defaults")
	}
}
