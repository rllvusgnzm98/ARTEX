package agent

import (
	"fmt"
	"strings"
)

type FootprintToggles struct {
	Pace          bool
	MinTouch      bool
	NoDirtyData   bool
	NoDestructive bool
	NoHarmOthers  bool
}

func DefaultFootprint() FootprintToggles {
	return FootprintToggles{true, true, true, true, true}
}

// 作业脚印规则由任务开关选择,不可被 DB 正文覆盖。
const (
	footprintPace          = "礼貌优先:平台会对经其记录/出口代理的目标流量按主机礼貌限速,你仍须自控并发与频率——不开超高并发洪泛,不做全端口/全字典的无脑狂扫;被限速或告警即降速、换出口、缩面,别和防护硬顶。"
	footprintMinTouch      = "最小触达:能被动/只读验证就不主动写;优先用一次性、可证伪的最小请求拿到判据,拿到即停,不重复捶打同一点。"
	footprintNoDirtyData   = "不留脏数据:注册/下单/支付/发帖/上传这类写操作只在必要时做,用可识别的测试标记、尽量自建可回收的测试数据,事后登记待清理;禁止批量写入、删除、改动他人数据或触发真实交易/通知。"
	footprintNoHarmOthers  = "不伤他人:缓存投毒、请求走私、竞态这类可能波及其他用户的手法,只用指向自己账号/自己缓存键的无害请求自证分歧,严禁把脏响应或走私流量落到真实用户。"
	footprintNoDestructive = "不做破坏性或不可逆动作:DoS/资源耗尽类仅做到证明即止,绝不持续打垮目标。"
)

func workerFootprintRulesFor(fp FootprintToggles) string {
	var lines []string
	for _, rule := range []struct {
		on   bool
		text string
	}{
		{fp.Pace, footprintPace},
		{fp.MinTouch, footprintMinTouch},
		{fp.NoDirtyData, footprintNoDirtyData},
		{fp.NoHarmOthers, footprintNoHarmOthers},
		{fp.NoDestructive, footprintNoDestructive},
	} {
		if rule.on {
			lines = append(lines, fmt.Sprintf("%d. %s", len(lines)+1, rule.text))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	if len(lines) < 5 {
		lines = append(lines, "操作员已为本任务授权放宽部分脚印限制,仍须保留证据与产物。")
	}
	return "\n\n**作业脚印红线(不可编辑)**:\n" + strings.Join(lines, "\n")
}
