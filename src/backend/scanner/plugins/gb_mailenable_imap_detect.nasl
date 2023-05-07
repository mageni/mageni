# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149599");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 09:04:40 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MailEnable Detection (IMAP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/mailenable/detected");

  script_tag(name:"summary", value:"IMAP based detection of MailEnable.");

  exit(0);
}

include("imap_func.inc");
include("port_service_func.inc");

port = imap_get_port(default: 143);

if (!banner = imap_get_banner(port: port))
  exit(0);

# OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] Welcome to MailEnable POP3 Server.
if ("Welcome to MailEnable" >< banner) {
  version = "unknown";

  set_kb_item(name: "mailenable/detected", value: TRUE);
  set_kb_item(name: "mailenable/imap/detected", value: TRUE);
  set_kb_item(name: "mailenable/imap/port", value: port);
  set_kb_item(name: "mailenable/imap/" + port + "/concluded", value: banner);
  set_kb_item(name: "mailenable/imap/" + port + "/version", value: version);
}

exit(0);
