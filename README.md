# MEGAMU automation — runtime address resolution

O cliente (Unity/IL2CPP) é atualizado com frequência e **ofusca nomes de métodos e muda os endereços (RVAs)**
a cada build. Por isso **nunca fixe RVA** em scripts que usam Frida neste jogo. Use o resolvedor.

## Resolvedor: [il2cpp_resolve.py](il2cpp_resolve.py)

```python
import frida, il2cpp_resolve
session = frida.attach(pid)
r = il2cpp_resolve.resolve_all(session, log=print)
# r["rva"]     -> {"AWAKE","COORD_CTOR","CAMERA_GET_MAIN","CAMERA_W2S_INJECTED","SCREEN_W","SCREEN_H","GET_LOCAL_BODY","MOVE_TO"}  (strings hex)
# r["offsets"] -> {"Index","Name","TargetCoordinates","Position"}  (offsets de campo de Body)
# uso no JS do Frida: gameBase.add(r["rva"]["AWAKE"])
```

`rugard_gui.py` mostra o padrão: `JS_TEMPLATE` com `@@NOME@@` + `build_js(r)` substituindo pelos valores resolvidos.

### Como cada coisa é achada (via API exportada `il2cpp_*` da `GameAssembly.dll`)
| Item | Estratégia |
|---|---|
| Classes do jogo (`Body`, `Coord`, `GameContext`, `LocalCharacterBody`) | por **nome**, só na `Assembly-CSharp` (namespace é `Mega` ou vazio — ignorado; `Coord` também existe em `mscorlib`) |
| `Body.Awake`, `Camera.get_main`, `Camera.WorldToScreenPoint_Injected`, `Screen.get_width/height`, `Coord..ctor(int,int)` | nome **não ofuscado** (Unity/engine) |
| Função que retorna o personagem local | método **estático sem parâmetros** em `GameContext` com retorno `*LocalCharacterBody` |
| Offsets de `Body` | `il2cpp_class_get_field_from_name` + `il2cpp_field_get_offset` |
| **Andar até (`MoveTo`)** | **único caso ambíguo**: 5 overloads idênticos `(Coord,float,UnityAction,bool,bool)->bool` em `LocalCharacterBody`; a ordem **não é estável** entre builds → **calibração por comportamento** |

### Calibração do movimento
Com várias contas: a **primeira da lista** calibra (`ensure_move(primary=True)`), as outras esperam e reaproveitam o cache; o hook do `Body.Awake` sobe antes da calibração (`resolve_all(..., allow_calibrate=False)`), então nenhum spawn é perdido. Na 1ª execução de cada build (chave = tamanho+mtime da `GameAssembly.dll`), testa TODOS os overloads (4 tiles em até 4
direções cada) e escolhe o mais confiável: retorna `0` (enfileirou) **e** chega em ≥3 de 4. (Overload "que passa em 2 direções" já falhou ao vivo devolvendo 1 sem andar.)
Resultado em `rva_cache.json` ao lado do script/.exe. **O personagem da 1ª conta precisa estar parado.**
Se o resolvedor disser `nao consegui resolver: X`, aquele item mudou de nome/assinatura: ver `tools/` e `research/`.

## Fatos do jogo úteis para outros projetos
- Posição de entidade: `Body.TargetCoordinates` (ref para `Coord`: X int@+0x10, Y int@+0x14); posição Unity real: `Body.Position` (Vector3). Offsets atuais: Index 0x20, Name 0x28, TargetCoordinates 0x70, Position 0x120 (leia do resolvedor, não fixe).
- `Body.Awake` não tem `Name`/coords preenchidos no instante da chamada: capture o ponteiro e leia por polling (~30 ms) até `Name` ficar não-nulo.
- NPCs/monstros `Body.Index < 10000`; jogadores 18000+.
- Clique no NPC só abre o diálogo a **~4–7 tiles** (alcance medido entre 4,0 e 6,9). Clicar longe não faz nada.
- Clicar enquanto outro comando de movimento está em curso pode cancelar a interação → retry loop.

## Ferramentas ([tools/](tools/))
- `resolve_test.py <pid> [ordinal]` — imprime tudo que o resolvedor acha.
- `probe.py <pid> <substr>...` — lista classes por nome (diagnóstico quando algo some).
- `move_test.py <pid> <ordinal> <dx>` — testa um overload de movimento (move o personagem!).
- `headless_run.py <nick> <log>` — roda o fluxo do Rugard sem GUI.

## Build do .exe
`pyinstaller --onefile --noconsole --name RugardAutoClick --distpath dist --workpath build_tmp --specpath build_tmp rugard_gui.py`
(`ui_templates/` deve ficar ao lado do .exe; `rva_cache.json` é gravado ao lado dele.)

## Ainda com RVAs fixos (precisam ser portados para `il2cpp_resolve`)
`chest_pickup.py`, `event_full_flow_test.py`, `rugard_gui_legacy.py`.
