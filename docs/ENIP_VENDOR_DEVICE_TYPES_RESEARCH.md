# EtherNet/IP Vendor ID and Device Type names: research

Retrieved 2026-11-02. Primary sources only (ODVA). Anything I could not read myself is marked "unverified".

## Question

`ListIdentity` in `lib/detect/enip_decode.go` gives us the CIP Identity Vendor ID (uint16) and Device Type (uint16). Can we map them to names (vendor 1 = Rockwell Automation/Allen-Bradley, device type 0x0C = Communications Adapter) using ODVA sources, and may we ship such a table in this GPL repo?

## Short answer

- ODVA assigns Vendor IDs. Its only public listing is a web search page (the ODVA Marketplace), with no download and no stated reuse terms. No machine-readable list was found.
- Device Type codes are defined in CIP Networks Library Volume 1 (paid, annual subscription). ODVA's free overview PUB00123 reportedly has a profile table; I could not read the PDF (unverified).
- No primary source says we may redistribute either list. We cannot confirm that it is safe to ship a table. This is a doubt, not a conclusion.
- Do not copy tables from Wireshark or Suricata. Keep unknown IDs as numbers with name "unknown".

## Vendor IDs

Authority and assignment.
- ODVA assigns the Vendor ID. It is "the unique number assigned by ODVA to your company" and is recorded in product firmware. Source: https://www.odva.org/technology-standards/getting-started/ (retrieved 2026-11-02).
- A VID is bought with a spec subscription. Source: https://www.odva.org/spec-vid-ctsoftware-order-form/ (retrieved 2026-11-02, "must have a current subscription to the specification").
- The Terms of Usage define a VID as a number "for a particular Licensed Technology" assigned to a Licensed Vendor. Quote came via a search summary of https://www.odva.org/wp-content/uploads/2026/01/PUB00357R1_WATERMARKED_ODVA_Application_and_Agreement_for_Membership_and_Terms_of_Usage.pdf. I did not read the PDF myself: unverified. The same summary says a vendor must not loan or assign its VID except to approved Affiliates (unverified).

Public listing.
- ODVA says VIDs are published "in its electronic file listing of Licensed Vendors with ODVA CONFORMANT products" (Getting Started page above). I found no link to that file and no file. Not found.
- The Test Services page links "View Licensed Vendors" to https://marketplace.odva.org/organizations#?technologies=none&view=all (https://www.odva.org/subscriptions-services/test-services/, retrieved 2026-11-02). It is a web page, not a PDF or XLS. No version or date is shown.
- The Marketplace page has an A-Z vendor browse and company search, with no visible export and no visible terms of use. The listing rows I got showed company names and product counts, not Vendor IDs (https://marketplace.odva.org/organizations, retrieved 2026-11-02). A search summary says each member page shows the VID (https://www.odva.org/communities/memberplace/market-your-products): unverified.
- Sample rows with IDs: none. I did not retrieve any ID-to-name pairs from ODVA.
- Important limit: the Marketplace lists a company only once it holds at least one Declaration of Conformity. Vendors that bought a VID but never certified a product may be absent. Source: marketplace.odva.org/organizations text, retrieved 2026-11-02.
- The LLDP MIB request form links "Look up your Vendor ID" to the same Marketplace directory (https://www.odva.org/subscriptions-services/additional-tools/request-lldp-management-information-base/, retrieved 2026-11-02).

Format and terms: web HTML only; no stated redistribution terms found; page footer is "© 2026 ODVA. All Rights Reserved." (spec order form page, retrieved 2026-11-02).

## Device types

- The Identity object's Device Type says which device profile the device uses. A device profile maps one-to-one to a device type. Table of codes: CIP Networks Library Volume 1, Chapter 6 (reported by an ODVA overview; see PUB00123 below, unverified).
- Volume 1 is sold by annual subscription; the current edition is CIP Volume 1 v3.40 (April 2026). No price is shown. Source: https://www.odva.org/subscriptions-services/specifications/ (retrieved 2026-11-02).
- Free first-party source: ODVA's overview "Common Industrial Protocol (CIP) and the Family of CIP Networks", https://www.odva.org/wp-content/uploads/2020/06/PUB00123R1_Common-Industrial_Protocol_and_Family_of_CIP_Networks.pdf (134-page tree count in PDF metadata, retrieved 2026-11-02). A search summary says it contains a table of Volume 1 profile numbers including 0x2B Generic Device (keyable), 0x02 AC Drives, 0x16 Motor Starter, 0x0E PLC. I could not extract the PDF text (no PDF tooling here). Unverified: whether the table is complete or current, and whether it is in the 2020 revision only.
- The EtherNet/IP developer guide PUB00213R0 says Device Type reflects the device profile and Product Code is vendor-chosen (search summary, unverified): https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf.
- The summary also says vendor-specific device types use other ranges and the rest are reserved by CIP (unverified; exact ranges not confirmed).
- The "keyable" meaning (a generic profile whose Device Type is used for electronic keying, with vendor-defined behaviour) is not confirmed from the spec text. The summary only says 0x2B is the fallback for devices that fit no specialised profile (unverified).
- I did not verify any of the example codes in the task (0x00, 0x07, 0x0C) against ODVA text. Do not use them until checked.

## Licensing and redistribution

- ODVA states the specs are subject to its Application and Agreement for Membership and Terms of Usage (https://www.odva.org/spec-vid-ctsoftware-order-form/, retrieved 2026-11-02). I could not read the text of that agreement or the spec license. Whether it limits republishing facts from the spec is unknown.
- The Marketplace and spec pages carry a general copyright notice and no open licence. I found no ODVA statement permitting or forbidding reuse of the ID-to-name list.
- Law (not ODVA text, and not legal advice): bare number-to-name facts are generally not copyrightable in many jurisdictions, but a compiled table can have database rights (EU) and the spec text is copyrighted. Doubt: this needs a lawyer or a written answer from ODVA. I found no primary source on this.
- Wireshark `packet-cip.c`, Suricata and similar tables are third-party GPL works. They are not a primary source. Copying them is a licence question and a copy of someone else's compilation. Use them at most as a cross-check; record nothing from them in the repo. No third-party licence text was read for this note.
- Attribution: no ODVA attribution terms found. If we ship names, cite ODVA as the source and note the retrieval date. "CIP", "EtherNet/IP" and "ODVA" are ODVA trademarks (the pages use the TM marks); nominative use only.

## Handling unknown values

- Size: no primary count found. The Marketplace page listed roughly 340 organizations before its output was cut off, and that covers only certified vendors (unverified estimate, from my read of https://marketplace.odva.org/organizations). Vendor IDs are uint16, so the ceiling is 65535.
- Change rate: no primary statement. New VIDs are issued whenever a company buys one, so the list grows continuously.
- Plan, as already decided: keep the numeric ID in the record and set the name to "unknown" when not in the table. Never drop or fail a packet because of an unknown ID.
- Store the table version and retrieval date next to any shipped table so stale data is visible.

## Open questions

1. Is there an ODVA-published downloadable Licensed Vendors file (the "electronic file listing")? Ask ODVA (membership/support contact on odva.org).
2. May we redistribute VID-to-name pairs and Device Type names in a GPL project? Ask ODVA in writing.
3. Does PUB00123 (or a newer free ODVA document) contain a complete Device Type table? Read the PDF directly and confirm codes.
4. Do Marketplace member pages show the VID per company? Need a manual look.
5. How are renamed vendors, acquisitions and VID transfers shown? Not verified (see pitfalls).
6. Reserved and vendor-specific Device Type ranges, and Vendor ID 0: no primary text read.

Pitfalls to check, all unverified because no primary text was read:
- Vendor ID 0 is probably reserved or invalid. Treat as "none/unknown" until confirmed.
- Product names already carry the vendor (for example a Rockwell product string starting with the brand). Do not prefix the vendor name on display.
- The Terms of Usage allow VID assignment to approved Affiliates, so one VID can map to a group of companies, and a company can be renamed or bought while keeping its VID. Show the name as of the table date. Rockwell Automation and Allen-Bradley share one VID in practice, but I did not verify this from ODVA.
- A vendor may hold different VIDs per technology ("for a particular Licensed Technology"), though ODVA's summary says the same ID is generally used across CIP networks. Not a problem for EtherNet/IP only.
- The Identity object has a newer "Supported Device Type Revision" attribute (38) in a recent change list (https://www.odva.org/wp-content/uploads/2025/12/PUB00317_ODVA-specification-mandatory-change-list_R22.pdf, search summary, unverified). It does not change the Device Type lookup.

## Sources

- https://www.odva.org/technology-standards/getting-started/ (fetched 2026-11-02)
- https://www.odva.org/spec-vid-ctsoftware-order-form/ (fetched 2026-11-02)
- https://www.odva.org/subscriptions-services/specifications/ (fetched 2026-11-02; Volume 1 v3.40, April 2026)
- https://www.odva.org/subscriptions-services/test-services/ (fetched 2026-11-02)
- https://marketplace.odva.org/organizations (fetched 2026-11-02; first 100,000 of 164,517 characters read)
- https://www.odva.org/subscriptions-services/additional-tools/request-lldp-management-information-base/ (fetched 2026-11-02)
- https://www.odva.org/wp-content/uploads/2020/06/PUB00123R1_Common-Industrial_Protocol_and_Family_of_CIP_Networks.pdf (PDF not readable here; search summary only)
- https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf (PDF not readable here; search summary only)
- https://www.odva.org/wp-content/uploads/2026/01/PUB00357R1_WATERMARKED_ODVA_Application_and_Agreement_for_Membership_and_Terms_of_Usage.pdf (search summary only)
- https://www.odva.org/wp-content/uploads/2026/06/PUB00008R8-Policy-on-Compliant-Products.pdf (PDF not readable here; not quoted)
- https://www.odva.org/wp-content/uploads/2025/12/PUB00317_ODVA-specification-mandatory-change-list_R22.pdf (search summary only)
