# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102066");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 08:27:17 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Openmediavault Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rpms_or_debs/gathered");

  script_tag(name:"summary", value:"SSH login-based detection of Openmediavault.");

  script_xref(name:"URL", value:"https://www.openmediavault.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

debs = get_kb_item("ssh/login/packages");
if(debs && debs =~ "openmediavault.+network attached storage solution") {
  # e.g.:
  # ii  openmediavault  2.1  all  Open network attached storage solution
  # ii  openmediavault  6.5.7-1  all  openmediavault - The open network attached storage solution
  vers = eregmatch(pattern:'ii\\s+openmediavault\\s+([0-9.]+)[^\r\n]+', string:debs);
  if(vers[1]) {
    version = vers[1];
    concluded = "DPKG package query: " + vers[0];
  }
}


if(version) {

  path = "";

  set_kb_item( name:"openmediavault/detected", value:TRUE );

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:openmediavault:openmediavault:");
  if(!cpe)
    cpe = "cpe:/a:openmediavault:openmediavault";

  register_product(cpe:cpe, location:path, port:0, service:"ssh-login");

  log_message(data:build_detection_report(app:"Openmediavault",
                                          version:version,
                                          install:path,
                                          cpe:cpe,
                                          concluded:concluded),
              port:0);
}

exit(0);
