# sip 库 Bug 记录 (发现于 GB28181 集成过程中)

## BUG-1: `Transport.Send` 丢弃发往 IPv4 字面量地址的 UDP 数据报 (已修复)

**文件**: `transport.go` (`pickAddrFamily`)

**现象**: 当 `NewTransport("0.0.0.0", ...)` 创建的 UDP socket 是 IPv6 双栈时
(`LocalAddr()` 返回 `::`),向字面量 IPv4 地址(如 `127.0.0.1`)发送数据报会
静默丢失:`Send()` 返回 `nil`,但接收方永远收不到。

**根因**: `pickAddrFamily` 在本地 socket 族(非 v4)与目标族(v4)不匹配时返回
`nil`,随后 `Send` 回退到 DNS 解析并可能把 v4 目标解析成 v6 形式发到错误的
地址族命名空间。

**修复**: 双栈 socket(Go 默认 `IPV6_V6ONLY=0`,本地地址为未指定 `::`)时,
把 v4 字面量转换成 4 字节形式直接写出,由内核自动映射。

**回归测试**: `TestSendUDPToLiteralV4FromDualStack` (transport_test.go)

## BUG-2: `ParseAuth` / `splitAuthParams` 只按逗号分隔参数 (已修复)

**文件**: `headers.go`

**现象**: Digest 参数仅以空格分隔的 Authorization / WWW-Authenticate 头
(常见于 GB28181 设备)解析时,只有第一个参数生效,`nonce`/`response` 等
全部丢失,导致摘要鉴权永远失败;`Auth.Value()` 渲染的 scheme 后第一个逗号
(如 `Digest, realm="..."`)还会使 scheme 被解析成 `"Digest,"`。

**修复**: `splitAuthParams` 现在在引号外按逗号或空白分隔参数;
`ParseAuth` 的 scheme 以首个空白或逗号为界。

## BUG-3(GBK 相关说明): XML 声明 `encoding="GB2312"` 会解析失败

**文件**: `gb28181/xml.go` 内通过 `CharsetReader` 透传解决(按原字节解码,
重新发布为 UTF-8)。上游标准设备常见 GB2312 声明,注意媒体层以外的中文
字段应使用 UTF-8 或在应用层做转码。
