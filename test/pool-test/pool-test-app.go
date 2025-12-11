package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	maxOpenConns := 5
	maxIdleConns := 2
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(time.Hour)

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, data TEXT)")
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	fmt.Println("=== Connection Pool Test App Started ===")
	fmt.Printf("MaxOpenConns: %d, MaxIdleConns: %d\n", maxOpenConns, maxIdleConns)
	fmt.Println("")

	var wg sync.WaitGroup
	acquireCount := int64(0)
	releaseCount := int64(0)
	var mu sync.Mutex

	phase1 := func() {
		fmt.Println("Phase 1: Normal operations (100 inserts)")
		for i := 0; i < 100; i++ {
			_, err := db.Exec("INSERT INTO test (data) VALUES (?)", fmt.Sprintf("data-%d", i))
			if err != nil {
				log.Printf("Failed to execute query: %v", err)
				continue
			}

			mu.Lock()
			acquireCount++
			releaseCount++
			mu.Unlock()

			if i%10 == 0 {
				fmt.Printf("  Insert %d completed\n", i)
			}

			time.Sleep(50 * time.Millisecond)
		}
		fmt.Println("Phase 1 completed")
		fmt.Println("")
	}

	phase2 := func() {
		fmt.Println("Phase 2: Concurrent queries (20 queries)")
		for i := 0; i < 20; i++ {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM test").Scan(&count)
			if err != nil {
				log.Printf("Query failed: %v", err)
			} else {
				mu.Lock()
				acquireCount++
				releaseCount++
				mu.Unlock()
			}
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println("Phase 2 completed")
		fmt.Println("")
	}

	phase3 := func() {
		fmt.Println("Phase 3: Pool exhaustion test (10 concurrent connections)")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				conn, err := db.Conn(ctx)
				if err != nil {
					fmt.Printf("  Connection %d: Failed to acquire (pool exhausted): %v\n", id, err)
					return
				}
				defer conn.Close()

				mu.Lock()
				acquireCount++
				mu.Unlock()

				fmt.Printf("  Connection %d: Acquired\n", id)
				time.Sleep(2 * time.Second)

				mu.Lock()
				releaseCount++
				mu.Unlock()

				fmt.Printf("  Connection %d: Released\n", id)
			}(i)
		}
		wg.Wait()
		fmt.Println("Phase 3 completed")
		fmt.Println("")
	}

	phase4 := func() {
		fmt.Println("Phase 4: Continuous operations (running indefinitely)")
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			var count int
			err := db.QueryRow("SELECT COUNT(*) FROM test").Scan(&count)
			if err != nil {
				log.Printf("Query failed: %v", err)
				continue
			}

			mu.Lock()
			acquireCount++
			releaseCount++
			currentAcq := acquireCount
			currentRel := releaseCount
			mu.Unlock()

			if currentAcq%10 == 0 {
				fmt.Printf("Running: %d acquires, %d releases\n", currentAcq, currentRel)
			}
		}
	}

	phase1()
	phase2()
	phase3()

	mu.Lock()
	totalAcq := acquireCount
	totalRel := releaseCount
	mu.Unlock()

	fmt.Printf("=== Summary ===\n")
	fmt.Printf("Total acquires: %d\n", totalAcq)
	fmt.Printf("Total releases: %d\n", totalRel)
	fmt.Printf("Reuse rate: %.2f%%\n", float64(totalRel)/float64(totalAcq)*100)
	fmt.Println("")
	fmt.Println("Starting continuous operations...")
	fmt.Println("")

	phase4()
}
