# SPEAR v3 research gap addendum

기준일: 2026-07-23  
대상: `docs/product/spear-v3-prd.md`  
질문: 최신 논문을 기준으로 현재 coverage에서 추가로 공격해야 할 실질적 빈틈이 있는가?

## Decision

`Fact` 추가할 빈틈이 있었다.

`Inference` 새로운 핵심은 payload 종류가 아니라 **capability가 시간에 따라 바뀌는 경우, provenance가 transformation에서 사라지는 경우, 여러 허용된 흐름이 결합되는 경우, intermediary가 같은 입력을 다르게 해석하는 경우**다.

`Inference` 논문에서 제안된 모든 공격을 “지원”으로 선언해서는 안 된다. 동료심사된 공격은 concrete fixture와 acceptance criterion으로, 최신 preprint는 falsifiable research hypothesis로 반영한다.

## 1. Peer-reviewed or accepted evidence

| Research | Evidence maturity | Security insight | SPEAR change |
|---|---|---|---|
| [Beyond the Protocol: MCP attack vectors, IEEE TSE 2026](https://doi.org/10.1109/TSE.2026.3694876) | Peer-reviewed journal | tool poisoning, puppet, rug pull, malicious external resource는 연결 시점이 아니라 tool identity/metadata/lifecycle 전체를 공격한다. | `FR-456`, `AC-430`, `AC-431`, `RH-201` |
| [Confused Deputy Attack Against MCP, ACM TOSEM 2026](https://doi.org/10.1145/3830467) | Peer-reviewed journal | 악성 server metadata가 benign tool을 shadowing해 tool selection과 payload execution을 가로챌 수 있다. | tool namespace/metadata snapshot, selection witness |
| [MCPTox, AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/view/40895) | Peer-reviewed conference | real-world MCP server의 tool description/schema poisoning을 agent별로 평가한다. | MCP shadowing/poisoning ground-truth corpus |
| [Conjunctive Prompt Attacks, ACL 2026](https://aclanthology.org/2026.acl-long.1577/) | Peer-reviewed conference | 각각 benign한 trigger와 remote-agent template이 routing 뒤 결합될 수 있다. | 기존 conjunctive mutation을 propagation lineage와 결합 |
| [MSA: Cross-MCP memory stealing, WPES 2025](https://doi.org/10.1145/3733802.3764057) | Peer-reviewed workshop | parasitic tool parameter가 다른 MCP/session context를 argument에 포함시켜 유출할 수 있다. | `FR-461`, `FR-512`, `AC-436`, `RH-207` |
| [CoreCrisis, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) | Peer-reviewed conference | benign interaction으로 state machine을 학습하고 underexplored state를 mutation하면 인증 우회와 logic bug를 찾을 수 있다. | `FR-213`, `FR-214`, `AC-208`, `RH-204` |
| [WDFuzz, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/lin-zihan) | Peer-reviewed conference | hierarchical directed scheduling이 Java web application의 deeper target reachability를 개선했다. | graph/state hierarchical scheduling baseline |
| [XSSky, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/shi-youkun) | Peer-reviewed conference | source→sanitizer→sink 경로를 local executable harness로 보존하면 concrete sanitizer-evasion input을 찾을 수 있다. | `FR-426`, `AC-437`, `RH-205` |
| [Network-level prompt and trait leakage, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/jeong) | Accepted/prepublication | payload가 암호화돼도 visited destination과 timing metadata가 prompt/user trait을 누출할 수 있다. | `FR-463`, `AC-440`, `RH-208` |

## 2. Emerging preprints

| Research | Evidence maturity | Security insight | SPEAR treatment |
|---|---|---|---|
| [Bad Memory, July 2026](https://arxiv.org/abs/2607.14611) | Recent preprint | memory attack success와 persistence가 system/model/multi-session sequence에 따라 크게 달라진다. | transformation lineage와 horizon을 research hypothesis로 검증 |
| [GhostWriter, July 2026](https://arxiv.org/abs/2607.06595) | Recent preprint | memory injection과 retrieval-time activation을 다른 session으로 분리한다. | `FR-457`, `FR-458`, `AC-432`, `AC-433`, `RH-202` |
| [Prompt Injection as Role Confusion, 2026](https://arxiv.org/abs/2603.12277) | ICML 2026 paper/preprint page | 모델은 interface role tag보다 latent style/role을 authority로 오인할 수 있다. | 기존 role-style mutation을 execution metadata differential로 강화 |
| [AI Agents May Always Fall for Prompt Injections, 2026](https://arxiv.org/abs/2605.17634) | Position/preprint | flow misrepresentation, norm manipulation과 permitted-flow mixing을 contextual integrity로 평가한다. | `FR-460`, `FR-461`, `AC-435`, `AC-436`, `RH-207` |
| [Morris II AI worm](https://arxiv.org/abs/2403.02817) | Preprint | adversarial output이 RAG/email ecosystem을 통해 self-replicating chain을 만들 수 있다. | bounded propagation only: `FR-459`, `FR-812`, `AC-434`, `AC-807` |
| [Back-Reveal: backdoored tool use](https://arxiv.org/abs/2604.05432) | Recent preprint | fine-tuned agent의 semantic trigger가 tool-mediated exfiltration을 일으킬 수 있다. | controlled fixture regression only: `FR-462`, `AC-439`, `RH-208` |
| [WAFFLED](https://arxiv.org/abs/2503.10846) | Preprint | WAF와 downstream parser discrepancy가 filter bypass/request smuggling으로 이어질 수 있다. | isolated intermediary views: `FR-427`, `AC-438`, `RH-206` |
| [REST API access-policy oracles, 2026](https://arxiv.org/abs/2604.00702) | Preprint | paired authorization policy와 injection oracle을 stateful REST fuzzing에 통합할 수 있다. | 기존 paired-principal oracle의 breadth fixture 근거 |

## 3. New attack hypotheses added

### `GAP-R01` Capability identity and lifecycle

- benign tool과 유사한 name/description/schema로 selection hijack
- 승인 당시와 execution 당시 capability drift
- resource URI 또는 registry endpoint 교체
- harmless version에서 malicious version으로 rug pull

Proof requirement: connection/approval/execution snapshot, gateway-selected server와 actual tool effect가 하나의 receipt chain에 있어야 한다.

### `GAP-R02` Memory transformation and delayed activation

- raw evidence가 summary에서 truth claim으로 승격
- writer principal/trust label이 embedding 또는 compaction에서 손실
- retrieval 후 role/instruction으로 재해석
- 여러 session 뒤 sleeper activation
- inter-agent memory handoff에서 origin 손실

Proof requirement: poison write, every transformation, retrieval, activation과 forbidden effect lineage.

### `GAP-R03` Bounded agent contagion

- agent output이 다른 agent의 input으로 복제
- RAG, email, repository와 memory를 carrier로 재전파
- individually benign message가 다른 agent의 template과 결합

Safety requirement: self-replicating payload를 외부에 내보내지 않고 canary artifact, maximum hop와 owned sink로만 검증한다.

### `GAP-R04` Learned state-machine attack

- benign flow로 observed state와 transition 학습
- underexplored transition, unexpected equivalence와 undocumented fallback 탐색
- learned model과 source/specification disagreement attack

Limitation: learned state는 fact가 아니라 observation-based hypothesis다.

### `GAP-R05` Path-persistent sanitizer evasion

- source→decoder→normalizer→sanitizer→template/interpreter sink 경로 보존
- generic payload success가 아니라 concrete browser/process/DB canary effect 요구

### `GAP-R06` Intermediary parser differential

- WAF, gateway, framework와 origin이 duplicate parameter, encoding, content type와 request boundary를 다르게 해석
- parser disagreement만으로 finding을 만들지 않고 authorization/sink bypass가 있어야 한다.

### `GAP-R07` Contextual data-flow composition

- 개별 데이터 접근은 허용되지만 다른 recipient/purpose로 합쳐지면 위반
- parasitic tool parameter가 session context를 합법적인 필수 argument처럼 요구
- raw secret 문자열 없이 여러 source에서 protected claim을 유도

Proof requirement: subject, source, data class, derived claim, recipient, purpose와 transmission principle을 state oracle에 포함한다.

### `GAP-R08` Agent supply-chain and metadata privacy

- model/provider/adapter/prompt digest 변경 뒤 semantic-trigger behavior
- encrypted payload 외 destination/timing/size만으로 sensitive task/trait 추론

Treatment: 아직 general-purpose discovery를 주장하지 않고 controlled regression 및 held-out evaluation으로만 검증한다.

## 4. Ideas reviewed but not added as core support

- model weight backdoor의 unknown-trigger 자동 발견: target-specific calibration과 ground truth가 없어 core claim으로 부적합
- unrestricted self-propagating agent worm: containment risk가 제품 가치보다 큼
- production WAF/request-smuggling automation: shared infrastructure 위험 때문에 dedicated Twin 전용
- content-only prompt-injection detector: adaptive attack에 취약하며 SPEAR의 state/effect proof와 맞지 않음
- paper의 reported attack-success percentage를 제품 성능 목표로 복사: target/model/fixture가 달라 비교 불가능

## 5. Review verdict

### Facts

- `Fact` 논문 검토로 기존 PRD에 없던 8개 research gap을 확인했다.
- `Fact` MCP capability lifecycle, state-machine learning, path-persistent fuzzing과 cross-MCP memory theft는 동료심사 근거가 있다.
- `Fact` 최신 memory sleeper, contextual-flow, model-backdoor 항목은 아직 preprint 또는 제한된 setting의 결과다.

### Inference

- `Inference` SPEAR의 가장 강한 독자성은 공격 payload library가 아니라 **time-varying capability + transforming provenance + composed flow + witnessed state effect**를 한 graph에서 재현하는 데 있다.

### Stop conditions

- preprint-derived pack이 controlled fixture 밖에서 재현되지 않으면 기본 attack pack으로 승격하지 않는다.
- propagation containment 또는 provenance receipt integrity가 한 번이라도 실패하면 해당 campaign을 배포하지 않는다.
- parser disagreement, model anomaly 또는 traffic classifier 결과만 있고 forbidden state/privacy predicate가 없으면 vulnerability로 발표하지 않는다.
