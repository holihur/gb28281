# 交互时序图

本文档描述 `go-sip` 库核心场景的消息交互时序。所有图使用 Mermaid 语法。

## 目录

- [客户端 INVITE 建立通话（UAC ↔ UAS）](#客户端-invite-建立通话)
- [代理并行 fork INVITE](#代理并行-fork-invite)
- [代理对话内请求（INFO / BYE）](#代理对话内请求)
- [CANCEL 取消呼叫](#cancel-取消呼叫)
- [REGISTER 注册流程](#register-注册流程)
- [Digest 鉴权](#digest-鉴权)
- [INVITE 事务状态机](#invite-事务状态机)

---

## 客户端 INVITE 建立通话

UAC 通过 `UA.Invite` 发起，`ClientTx` 负责重传与超时，2xx 后自动建立 Dialog。

```mermaid
sequenceDiagram
    participant App as 应用层
    participant UAC as UA (Caller)
    participant CTX as ClientTx
    participant TP as Transport (UDP)
    participant UAS as UA (Callee)
    participant DM as DialogManager

    App->>UAC: Invite(target, from, ct, body)
    UAC->>UAC: 生成 Call-ID / local tag / CSeq=1
    UAC->>DM: Add(NewClientDialog)
    UAC->>CTX: tm.Request(req, dst)
    CTX->>TP: send INVITE (state=Calling)
    CTX-->>CTX: startRetransmit (T1 指数退避)

    TP->>UAS: INVITE
    UAS->>UAS: OnInvite 回调, NewServerDialog(local tag)
    UAS-->>TP: 100 Trying
    TP->>CTX: 100 (state=Proceeding)
    CTX->>CTX: deliver 事件 (dlg.updateFromResponse)
    UAS-->>TP: 200 OK (To-tag)
    CTX->>CTX: receive: 2xx → Completed, sendACK, TimerD
    CTX-->>UAC: 事件 200 OK
    UAC->>UAC: pump(): RemoteTag/RemoteTarget 更新, close(Done)
    CTX-->>TP: ACK

    App->>UAC: WaitResponse / Ack()
    App->>UAC: Hangup(dlg)
    UAC->>TP: BYE (dlg.CreateRequest)
    UAS-->>TP: 200 OK
    UAC->>DM: dialog.Terminate + Remove
```

---

## 代理并行 fork INVITE

`Proxy.handleInitial` 对初始 INVITE 按 `ResolveTargets` 返回的目标并行 fork，
第一个 2xx 胜出并取消其余分支；全部失败则按 `pickBestResponse` 转发最优失败码。

```mermaid
sequenceDiagram
    participant UAC as UA (Caller)
    participant STX as ServerTx
    participant P as Proxy
    participant CTX1 as ClientTx (branch A)
    participant CTX2 as ClientTx (branch B)
    participant UA as UA (Callee)

    UAC->>STX: INVITE (Call-ID, tag)
    STX->>P: handleRequest → handleInitial
    P->>P: resolveTargets(req) → [A, B]
    par branch A
        P->>P: prepareBranch(new Via+branch, Max-Forwards-1, Record-Route?)
        P->>CTX1: tm.Request → state=Calling
        CTX1->>UA: INVITE (branch A)
        P->>P: go runBranch(A)
    and branch B
        P->>CTX2: tm.Request → state=Calling
        CTX2->>UA: INVITE (branch B)
        P->>P: go runBranch(B)
    end

    UA-->>CTX1: 180 Ringing (provisional, 忽略)
    UA-->>CTX2: 200 OK
    CTX2-->>P: runBranch: 2xx → deliverFinal(B)
    P->>P: 标记 cancelled, Cancel(A)
    P->>P: dialogs[Call-ID] = {callerAddr, remoteLeg=B Contact}
    P->>P: Del(Via) 后 stx.Respond(200)
    STX-->>UAC: 200 OK
    CTX2-->>UA: ACK (自动重传)

    Note over P: Timer C 超时 → Cancel 所有分支, 回 504

    UAC->>P: ACK (端到端, handleAck 按 dialogs 转发到 remoteLeg)
```

### 失败聚合

```mermaid
sequenceDiagram
    participant P as Proxy
    participant CTX1 as branch A
    participant CTX2 as branch B
    participant STX as ServerTx

    CTX1-->>P: 486 Busy Here (final)
    P->>P: checkGroupDone: B 未 final, 等待
    CTX2-->>P: 480 Timeout (final)
    P->>P: checkGroupDone: 全部 final
    P->>P: pickBestResponse: 486 > 480
    P->>STX: Respond(486)
```

---

## 代理对话内请求

对话内请求（INFO / BYE 等）只按 Call-ID 匹配 dialog，并校验来源地址属于任一 leg（防伪造 BYE）。

```mermaid
sequenceDiagram
    participant UA as UA (Caller)
    participant STX as ServerTx
    participant P as Proxy
    participant CAL as Callee

    UA->>STX: INFO (Call-ID, 对话内)
    STX->>P: handleRequest → handleInitial → forwardInDialog
    P->>P: dialogs[Call-ID] 存在?
    P->>P: dialogSourceAllowed(src ∈ {callerAddr, remoteLeg})?
    alt 来源非法
        P-->>UA: 403 Forbidden
    else 来源合法
        P->>P: prepareBranch(new top Via+branch)
        P->>CAL: INFO → forwardAndCollect (60s)
        CAL-->>P: 200 OK
        P-->>UA: 200 OK
    end

    Note over P,BYE: BYE 成功转发后删除 dialog
    Note over P: 来源不匹配 → 403; dialog 不存在 → 481
```

---

## CANCEL 取消呼叫

CANCEL 必须与被取消的 INVITE 来自同一地址（RFC 3261 §9.1），否则在事务层直接丢弃。

```mermaid
sequenceDiagram
    participant UAC as UA (Caller)
    participant TM as TxManager (Proxy)
    participant P as Proxy
    participant CTX as ClientTx (branch)
    participant CAL as Callee

    UAC->>TM: INVITE (branch=z1)
    TM->>P: stx(INVITE) 创建
    UAC->>TM: CANCEL (branch=z1, 同一来源)
    TM->>TM: 校验 sameAddr(src, INVITE stx.src)
    TM->>P: handleRequest(CANCEL)
    P->>P: cancelled[group]=true; Cancel 所有未 final 分支
    P-->>UAC: 200 OK (CANCEL)
    CTX->>CAL: CANCEL (state=Proceeding)
    CAL-->>CTX: 487 Request Terminated
    CTX-->>P: 487 → deliverFinal/checkGroupDone → 转发上游
    P-->>UAC: 487 (INVITE)

    Note over TM: 来源不符的 CANCEL → 静默丢弃 (防拆线攻击)
```

---

## REGISTER 注册流程

代理默认拒绝转发 REGISTER（防开放中继），UA 侧由 `OnRegister` 回调处理。

```mermaid
sequenceDiagram
    participant App as 应用层
    participant UA as UA
    participant TP as Transport
    participant SRV as Registrar/Proxy

    App->>UA: Register(aor, contact, expires, creds)
    UA->>UA: Call-ID, CSeq=1 REGISTER, From tag, Expires/Contact
    UA->>TP: REGISTER → aor.Host:aor.EffectivePort()
    TP->>SRV: REGISTER
    alt 代理收到 REGISTER
        SRV-->>TP: 403 Forbidden (RelayRegister=false)
    else Registrar 收到 (UA 场景 OnRegister 回调)
        SRV-->>TP: 200 OK (Contact;expires)
        TP-->>UA: 200 OK
    end
```

---

## Digest 鉴权

收到 401/407 后用挑战构造 Digest 响应；算法支持 MD5（默认）、SHA-256、SHA-512-256（RFC 8760）。

```mermaid
sequenceDiagram
    participant UA as UA
    participant SRV as Server

    UA->>SRV: REGISTER (无凭据)
    SRV-->>UA: 401 Unauthorized (WWW-Authenticate: Digest realm, nonce, algorithm)
    UA->>UA: ParseAuth(challenge)
    UA->>UA: DigestResponse(challenge, method, uri, user, pass)
    Note over UA: HA1 = H(user:realm:pass)<br/>HA2 = H(method:uri)<br/>response = H(HA1:nonce:nc:cnonce:qop:HA2)
    UA->>SRV: REGISTER (Authorization: Digest ...)
    SRV-->>UA: 200 OK
```

---

## INVITE 事务状态机

客户端 INVITE 事务（含自动 ACK 与重传终止条件）。

```mermaid
stateDiagram-v2
    [*] --> Calling: tm.Request / send INVITE
    Calling --> Calling: 重传 (T1, 2×T1 上限)
    Calling --> Proceeding: 1xx
    Calling --> Completed: 2xx → sendACK, TimerD
    Calling --> [*]: TimerF 超时
    Proceeding --> Completed: 2xx → sendACK, TimerD
    Completed --> Confirmed: ACK (server 侧)
    Completed --> Terminated: TimerD
    Confirmed --> Terminated: TimerJ
    Terminated --> [*]

    note right of Calling: 非 INVITE 事务:<br/>Trying → Proceeding → Completed (T1×64 上限重传)
```
