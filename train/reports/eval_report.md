| group | n atk/ben | ours AUC | ours TPR@FPR≤1% | ours TPR / FPR @ cal. thr | ProtectAI AUC | ProtectAI TPR@FPR≤1% | ProtectAI TPR / FPR @0.5 |
|---|---|---|---|---|---|---|---|
| all | 1171/1005 | 0.976 | 0.485 | 0.957 / 0.074 | 0.784 | 0.262 | 0.886 / 0.506 |
| en | 562/364 | 0.978 | 0.486 | 0.957 / 0.069 | 0.897 | 0.351 | 0.868 / 0.234 |
| vi | 609/641 | 0.973 | 0.396 | 0.957 / 0.076 | 0.661 | 0.059 | 0.901 / 0.661 |
| en/data_exfiltration | 29/364 | 0.970 | 0.448 | 0.931 / 0.069 | 0.743 | 0.000 | 0.655 / 0.234 |
| en/direct_injection | 147/364 | 0.978 | 0.782 | 0.952 / 0.069 | 0.913 | 0.361 | 0.891 / 0.234 |
| en/indirect_injection | 60/364 | 0.973 | 0.167 | 0.917 / 0.069 | 0.826 | 0.000 | 0.700 / 0.234 |
| en/jailbreak | 65/364 | 0.947 | 0.123 | 0.877 / 0.069 | 0.877 | 0.138 | 0.877 / 0.234 |
| en/obfuscation | 48/364 | 0.978 | 0.000 | 1.000 / 0.069 | 0.819 | 0.000 | 0.833 / 0.234 |
| en/prompt_extraction | 173/364 | 0.993 | 0.734 | 0.988 / 0.069 | 0.984 | 0.780 | 0.983 / 0.234 |
| en/tool_poisoning | 40/364 | 0.977 | 0.000 | 1.000 / 0.069 | 0.814 | 0.000 | 0.725 / 0.234 |
| vi/data_exfiltration | 61/641 | 0.967 | 0.574 | 0.836 / 0.076 | 0.638 | 0.066 | 0.820 / 0.661 |
| vi/direct_injection | 134/641 | 0.984 | 0.649 | 0.978 / 0.076 | 0.626 | 0.030 | 0.940 / 0.661 |
| vi/indirect_injection | 133/641 | 0.977 | 0.316 | 0.992 / 0.076 | 0.692 | 0.105 | 0.872 / 0.661 |
| vi/jailbreak | 81/641 | 0.967 | 0.222 | 0.938 / 0.076 | 0.657 | 0.012 | 0.914 / 0.661 |
| vi/obfuscation | 34/641 | 0.960 | 0.059 | 0.941 / 0.076 | 0.774 | 0.206 | 1.000 / 0.661 |
| vi/prompt_extraction | 92/641 | 0.981 | 0.620 | 0.946 / 0.076 | 0.669 | 0.065 | 0.826 / 0.661 |
| vi/tool_poisoning | 74/641 | 0.951 | 0.000 | 1.000 / 0.076 | 0.634 | 0.000 | 0.986 / 0.661 |
| en/variant:leet | 40/364 | 0.976 | 0.000 | 1.000 / 0.069 | 0.892 | 0.000 | 0.900 / 0.234 |
| en/variant:orig | 522/364 | 0.978 | 0.523 | 0.954 / 0.069 | 0.898 | 0.377 | 0.866 / 0.234 |
| vi/variant:leet | 77/26 | 0.880 | 0.260 | 0.974 / 0.231 | 0.678 | 0.143 | 0.896 / 0.654 |
| vi/variant:no_diacritics | 174/236 | 0.966 | 0.385 | 0.943 / 0.076 | 0.653 | 0.075 | 0.937 / 0.686 |
| vi/variant:orig | 208/236 | 0.994 | 0.827 | 0.976 / 0.042 | 0.642 | 0.062 | 0.861 / 0.631 |
| vi/variant:teencode | 113/143 | 0.961 | 0.239 | 0.938 / 0.105 | 0.692 | 0.062 | 0.894 / 0.671 |
| vi/variant:translated | 37/641 | 0.987 | 0.838 | 0.946 / 0.076 | 0.839 | 0.054 | 1.000 / 0.661 |

Latency (INT8 ONNX, onnxruntime CPU, batch 1, model only):

| threads | 128 tok p50 / p99 ms | 256 tok p50 / p99 ms |
|---|---|---|
| default_threads | 17.46 / 30.22 | 33.39 / 59.22 |
| one_thread | 55.26 / 71.03 | 103.38 / 114.46 |

Category heads on eval attacks (head fires at its threshold / top-1 attack label = eval category):

| group | n | head fires | top-1 |
|---|---|---|---|
| en/data_exfiltration | 29 | 0.793 | 0.724 |
| en/direct_injection | 147 | 0.844 | 0.837 |
| en/indirect_injection | 60 | 0.900 | 0.817 |
| en/jailbreak | 65 | 0.708 | 0.708 |
| en/obfuscation | 48 | 1.000 | 0.938 |
| en/prompt_extraction | 173 | 0.734 | 0.225 |
| en/tool_poisoning | 40 | 0.875 | 0.500 |
| vi/data_exfiltration | 61 | 0.656 | 0.689 |
| vi/direct_injection | 134 | 0.851 | 0.821 |
| vi/indirect_injection | 133 | 0.970 | 0.805 |
| vi/jailbreak | 81 | 0.741 | 0.617 |
| vi/obfuscation | 34 | 0.853 | 0.676 |
| vi/prompt_extraction | 92 | 0.717 | 0.717 |
| vi/tool_poisoning | 74 | 1.000 | 0.541 |
