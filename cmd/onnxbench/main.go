// Command onnxbench measures per-input latency of internal/onnx models.
//
//	CGO_ENABLED=1 CGO_LDFLAGS=-L$PWD/.onnx/lib go run -tags onnx ./cmd/onnxbench \
//	    -model models/cache/protectai-deberta-v3-base-pi-v2 -kind classifier
//
// Each request scores one text of exactly -lengths tokens (special tokens
// included). -conc goroutines issue requests in parallel; the table reports the
// latency of single requests (p50/p99) and the aggregate throughput.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/promptshield/promptshield/internal/onnx"
)

const corpus = `Large language models follow instructions written in natural language, which makes them useful
and also exposes them to prompt injection. An attacker hides instructions inside a document, an email or a web
page, and the model treats them as if the user had written them. Guardrails inspect the input before it reaches
the model and score how likely it is that the text tries to override the system prompt. The gateway must stay fast,
so the classifier runs in process and long inputs are split into overlapping windows of tokens.`

func main() {
	modelDir := flag.String("model", "models/local/guardspec-classifier-v0", "model directory")
	kind := flag.String("kind", "classifier", "classifier or embedder")
	lengths := flag.String("lengths", "64,256,512", "input lengths in tokens, special tokens included")
	concs := flag.String("conc", "1,4", "concurrency levels")
	n := flag.Int("n", 100, "measured requests per (length, concurrency)")
	warmup := flag.Int("warmup", 5, "unmeasured requests first")
	intra := flag.Int("intra", 0, "ONNX Runtime intra-op threads per run (0: $INFERENCE_INTRA_OP_THREADS or ORT default)")
	flag.Parse()

	ver, err := onnx.RuntimeVersion()
	if err != nil {
		fatal(err)
	}
	type model interface {
		TokenCount(string) (int, error)
		Close() error
	}
	var (
		m   model
		run func(context.Context, string) error
	)
	switch *kind {
	case "classifier":
		c, err := onnx.NewClassifier(*modelDir, onnx.Options{IntraOpThreads: *intra})
		if err != nil {
			fatal(err)
		}
		m, run = c, func(ctx context.Context, s string) error { _, err := c.Score(ctx, []string{s}); return err }
	case "embedder":
		e, err := onnx.NewEmbedder(*modelDir, onnx.Options{IntraOpThreads: *intra})
		if err != nil {
			fatal(err)
		}
		m, run = e, func(ctx context.Context, s string) error { _, err := e.Embed(ctx, []string{s}); return err }
	default:
		fatal(fmt.Errorf("unknown -kind %q", *kind))
	}
	defer func() { _ = m.Close() }()

	fmt.Printf("model=%s kind=%s ort=%s os/arch=%s/%s cpus=%d %s=%d %s=%q -intra=%d\n\n",
		*modelDir, *kind, ver, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(),
		onnx.EnvMaxConcurrency, onnx.MaxConcurrencyFromEnv(), onnx.EnvIntraOpThreads, os.Getenv(onnx.EnvIntraOpThreads), *intra)
	fmt.Println("| tokens | conc | p50 ms | p99 ms | mean ms | req/s |")
	fmt.Println("|-------:|-----:|-------:|-------:|--------:|------:|")

	ctx := context.Background()
	for _, ls := range strings.Split(*lengths, ",") {
		want, _ := strconv.Atoi(ls)
		text, got := textOfTokens(m.TokenCount, want-2) // 2 special tokens for both model families
		for _, cs := range strings.Split(*concs, ",") {
			conc, _ := strconv.Atoi(cs)
			for i := 0; i < *warmup; i++ {
				if err := run(ctx, text); err != nil {
					fatal(err)
				}
			}
			lat := make([]time.Duration, 0, *n)
			var mu sync.Mutex
			var wg sync.WaitGroup
			jobs := make(chan struct{}, *n)
			for i := 0; i < *n; i++ {
				jobs <- struct{}{}
			}
			close(jobs)
			start := time.Now()
			for w := 0; w < conc; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range jobs {
						t0 := time.Now()
						if err := run(ctx, text); err != nil {
							fatal(err)
						}
						d := time.Since(t0)
						mu.Lock()
						lat = append(lat, d)
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			wall := time.Since(start)
			sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
			var sum time.Duration
			for _, d := range lat {
				sum += d
			}
			fmt.Printf("| %6d | %4d | %6.1f | %6.1f | %7.1f | %5.1f |\n", got+2, conc,
				ms(pct(lat, 50)), ms(pct(lat, 99)), ms(sum/time.Duration(len(lat))), float64(len(lat))/wall.Seconds())
		}
	}
}

// textOfTokens returns the longest prefix (in words) of a repeated corpus with
// at most n tokens, and its token count.
func textOfTokens(count func(string) (int, error), n int) (string, int) {
	words := strings.Fields(strings.Repeat(corpus+" ", 1+n/50))
	lo, hi := 1, len(words)
	for lo < hi { // largest k with count(words[:k]) <= n
		mid := (lo + hi + 1) / 2
		c, err := count(strings.Join(words[:mid], " "))
		if err != nil {
			fatal(err)
		}
		if c <= n {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	text := strings.Join(words[:lo], " ")
	c, _ := count(text)
	return text, c
}

func pct(s []time.Duration, p int) time.Duration {
	i := (len(s)*p + 99) / 100
	if i < 1 {
		i = 1
	}
	return s[i-1]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
