| group | n atk/ben | ours AUC | ours TPR@FPR≤1% | ours TPR / FPR @ cal. thr | ProtectAI AUC | ProtectAI TPR@FPR≤1% | ProtectAI TPR / FPR @0.5 |
|---|---|---|---|---|---|---|---|
| all | 1171/1005 | 0.984 | 0.625 | 0.930 / 0.035 | - | - | - / - |
| en | 562/364 | 0.988 | 0.838 | 0.927 / 0.014 | - | - | - / - |
| vi | 609/641 | 0.982 | 0.548 | 0.933 / 0.047 | - | - | - / - |
| en/data_exfiltration | 29/364 | 0.981 | 0.690 | 0.862 / 0.014 | - | - | - / - |
| en/direct_injection | 147/364 | 0.979 | 0.850 | 0.932 / 0.014 | - | - | - / - |
| en/indirect_injection | 60/364 | 0.994 | 0.917 | 0.917 / 0.014 | - | - | - / - |
| en/jailbreak | 65/364 | 0.971 | 0.662 | 0.815 / 0.014 | - | - | - / - |
| en/obfuscation | 48/364 | 0.991 | 0.750 | 0.896 / 0.014 | - | - | - / - |
| en/prompt_extraction | 173/364 | 0.998 | 0.948 | 0.971 / 0.014 | - | - | - / - |
| en/tool_poisoning | 40/364 | 0.994 | 0.700 | 1.000 / 0.014 | - | - | - / - |
| vi/data_exfiltration | 61/641 | 0.972 | 0.607 | 0.803 / 0.047 | - | - | - / - |
| vi/direct_injection | 134/641 | 0.992 | 0.776 | 0.985 / 0.047 | - | - | - / - |
| vi/indirect_injection | 133/641 | 0.991 | 0.729 | 1.000 / 0.047 | - | - | - / - |
| vi/jailbreak | 81/641 | 0.975 | 0.247 | 0.914 / 0.047 | - | - | - / - |
| vi/obfuscation | 34/641 | 0.980 | 0.088 | 1.000 / 0.047 | - | - | - / - |
| vi/prompt_extraction | 92/641 | 0.983 | 0.707 | 0.913 / 0.047 | - | - | - / - |
| vi/tool_poisoning | 74/641 | 0.968 | 0.108 | 0.838 / 0.047 | - | - | - / - |
| en/variant:leet | 40/364 | 0.981 | 0.200 | 0.850 / 0.014 | - | - | - / - |
| en/variant:orig | 522/364 | 0.988 | 0.887 | 0.933 / 0.014 | - | - | - / - |
| vi/variant:leet | 77/26 | 0.948 | 0.584 | 0.857 / 0.115 | - | - | - / - |
| vi/variant:no_diacritics | 174/236 | 0.980 | 0.580 | 0.914 / 0.059 | - | - | - / - |
| vi/variant:orig | 208/236 | 0.998 | 0.981 | 0.995 / 0.013 | - | - | - / - |
| vi/variant:teencode | 113/143 | 0.966 | 0.088 | 0.894 / 0.070 | - | - | - / - |
| vi/variant:translated | 37/641 | 0.992 | 0.838 | 0.946 / 0.047 | - | - | - / - |

Latency (INT8 ONNX, onnxruntime CPU, batch 1, model only):

| threads | 128 tok p50 / p99 ms | 256 tok p50 / p99 ms |
|---|---|---|
| default_threads | 11.00 / 13.56 | 19.90 / 23.07 |
| one_thread | 46.27 / 51.64 | 108.07 / 118.46 |

Category heads on eval attacks (head fires at its threshold / top-1 attack label = eval category):

| group | n | head fires | top-1 |
|---|---|---|---|
| en/data_exfiltration | 29 | 0.759 | 0.724 |
| en/direct_injection | 147 | 0.830 | 0.891 |
| en/indirect_injection | 60 | 0.867 | 0.767 |
| en/jailbreak | 65 | 0.631 | 0.662 |
| en/obfuscation | 48 | 1.000 | 0.917 |
| en/prompt_extraction | 173 | 0.711 | 0.324 |
| en/tool_poisoning | 40 | 1.000 | 0.375 |
| vi/data_exfiltration | 61 | 0.656 | 0.672 |
| vi/direct_injection | 134 | 0.896 | 0.918 |
| vi/indirect_injection | 133 | 0.880 | 0.707 |
| vi/jailbreak | 81 | 0.642 | 0.605 |
| vi/obfuscation | 34 | 0.882 | 0.676 |
| vi/prompt_extraction | 92 | 0.815 | 0.815 |
| vi/tool_poisoning | 74 | 0.892 | 0.473 |
