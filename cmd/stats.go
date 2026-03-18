package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"hyoketsu/db"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show database statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := db.Open(getDBPath())
		if err != nil {
			return err
		}
		defer store.Close()

		stats, err := store.Stats()
		if err != nil {
			return err
		}

		total, err := store.TotalCount()
		if err != nil {
			return err
		}

		cursor, _ := store.GetCursor()

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SOURCE\tCOUNT")
		for _, s := range stats {
			fmt.Fprintf(w, "%s\t%d\n", s.Source, s.Count)
		}
		fmt.Fprintf(w, "---\t---\n")
		fmt.Fprintf(w, "total\t%d\n", total)
		w.Flush()

		if cursor != "" {
			fmt.Printf("\nLast catalog cursor: %s\n", cursor)
		} else {
			fmt.Println("\nNo catalog cursor set. Run 'hyoketsu update' to populate the database.")
		}

		return nil
	},
}
