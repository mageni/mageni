# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149597");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 06:53:51 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MailEnable Detection (SMTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/mailenable/detected");

  script_tag(name:"summary", value:"SMTP based detection of MailEnable.");

  exit(0);
}

include("smtp_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default: 25);

banner = smtp_get_banner(port: port);
if (banner !~ "Mail(Enable| Enable SMTP) Service")
  exit(0);

version = "unknown";

set_kb_item(name: "mailenable/detected", value: TRUE);
set_kb_item(name: "mailenable/smtp/detected", value: TRUE);
set_kb_item(name: "mailenable/smtp/port", value: port);
set_kb_item(name: "mailenable/smtp/" + port + "/concluded", value: banner);

# 220 example.home ESMTP MailEnable Service, Version: 10.43-- ready at 04/28/23 04:52:19
# 220 example.home ESMTP Mail Enable SMTP Service, Version: 1.5018-- ready at Thu, 20 Apr 2023 22:17:45 +0300
vers = eregmatch(pattern: "Mail(Enable| Enable SMTP) Service, Version:\s*([0-9.]+)", string: banner);
if (!isnull(vers[2]))
  version = vers[2];

set_kb_item(name: "mailenable/smtp/" + port + "/version", value: version);

exit(0);
