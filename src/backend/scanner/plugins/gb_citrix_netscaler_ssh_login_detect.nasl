# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140667");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-12 09:26:50 +0700 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Citrix NetScaler Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("citrix_netscaler/found");

  script_tag(name:"summary", value:"SSH login based detection of Citrix NetScaler.");

  exit(0);
}

if (!system = get_kb_item("citrix_netscaler/system"))
  exit(0);

port = get_kb_item("citrix_netscaler/ssh/port");

set_kb_item(name: "citrix/netscaler/detected", value: TRUE);
set_kb_item(name: "citrix/netscaler/ssh/detected", value: TRUE);
set_kb_item(name: "citrix/netscaler/ssh/port", value: port);

version = "unknown";

# NetScaler NS11.0: Build 62.10.nc, Date: Aug 8 2015, 23:00:46
# NetScaler NS13.1: Build 49.13.nc, Date: Jul 10 2023, 12:00:59   (64-bit)
vers = eregmatch(pattern: "NetScaler NS([0-9\.]+): (Build (([0-9\.]+))(.e)?.nc)?", string: system);
if (!isnull(vers[1])) {
  if (!isnull(vers[3]))
    version = vers[1] + "." + vers[3];
  else
    version = vers[1];

  # Enhanced Build
  if (!isnull(vers[5]))
    set_kb_item(name: "citrix/netscaler/enhanced_build", value: TRUE);

  set_kb_item(name: "citrix/netscaler/ssh/" + port + "/concluded", value: system);
}

set_kb_item(name: "citrix/netscaler/ssh/" + port + "/version", value: version);

exit(0);
