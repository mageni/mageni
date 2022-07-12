###############################################################################
# OpenVAS Vulnerability Test
#
# Filr Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105824");
  script_version("2020-12-16T08:51:38+0000");
  script_tag(name:"last_modification", value:"2020-12-16 11:44:11 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2016-07-25 16:02:26 +0200 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Micro Focus (Novell) Filr Detection (SSH-Login)");

  script_tag(name:"summary", value:"SSH based detection of Micro Focus (Novell) Filr.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("filr/ssh/rls");

  exit(0);
}

include("host_details.inc");

if (!rls = get_kb_item("filr/ssh/rls"))
  exit(0);

if ("Filr" >!< rls)
  exit(0);

port = get_kb_item("filr/ssh/port");

version = "unknown";

set_kb_item(name: "microfocus/filr/detected", value: TRUE);
set_kb_item(name: "microfocus/filr/ssh-login/port", value: port);
set_kb_item(name: "microfocus/filr/ssh-login/" + port + "/concluded", value: chomp(rls));

# product=Novell Filr Appliance
# singleWordProductName=Filr
# version=2.0.0.421
# arch=x86_64
# id=filr-appliance
#
# product=Filr Appliance
# singleWordProductName=Filr
# version=4.0.0.155
# arch=x86_64
# id=filr-appliance
# updateRegcodeKey=regcode-filr
# updateProductName=Filr4.0
vers = eregmatch(pattern: "version=([0-9.]+)", string: rls);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "microfocus/filr/ssh-login/" + port + "/version", value: version);

exit(0);
