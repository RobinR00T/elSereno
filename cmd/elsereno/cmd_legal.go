package main

import (
	"github.com/spf13/cobra"
)

const legalBanner = `ElSereno — acceptable use policy

By running this binary you acknowledge:

  - You are authorised, in writing, by the owner of the target systems.
  - Your activity stays within the scope, time window, and target list
    defined in that authorisation.
  - You will not induce denial of service, degrade safety, or tamper
    with industrial control or lift-alarm equipment.

GDPR notice: IPs, banners, IMSI/IMEI, and phonebook entries may qualify
as personal data. The operator is the data controller.

See LEGAL.md for the full text.
`

func newLegalCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "legal",
		Short: "Print the acceptable-use policy disclaimer",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Print(legalBanner)
			return nil
		},
	}
}
