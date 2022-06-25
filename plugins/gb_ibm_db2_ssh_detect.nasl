##############################################################################
# OpenVAS Vulnerability Test
# Description: IBM Db2 Detection (SSH-Login)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900217");
  script_version("2020-03-10T09:38:22+0000");
  script_tag(name:"last_modification", value:"2020-03-10 09:38:22 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("IBM Db2 Detection (SSH-Login)");

  script_copyright("Copyright (C) 2008 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");

  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script performs a SSH based detection of IBM Db2 Server.");
  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

port = kb_ssh_transport();
sock = ssh_login_or_reuse_connection();

if (!sock)
  exit(0);

db2ls_res = ssh_cmd(socket: sock, cmd: "db2ls -a", timeout: 120);
ssh_close_connection();

# Install Path                       Level   Fix Pack   Special Install Number   Install Date                  Installer UID
#---------------------------------------------------------------------------------------------------------------------
#/opt/ibm/db2/V11.5               11.5.0.0        0                            Fri Jun 28 23:03:08 2019 UTC             0
if (!db2ls_res || "Install Path" >!< db2ls_res)
    exit(0);

version = "unknown";
fix_pack = "unknown";

set_kb_item(name: "ibm/db2/detected", value: TRUE);
set_kb_item(name: "ibm/db2/ssh-login/port", value: port);

vers = eregmatch(pattern:" ([0-9.]+)", string: strstr(db2ls_res, '/'));
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "ibm/db2/ssh-login/" + port + "/concluded", value: db2ls_res);
}

fp = eregmatch(pattern: " [0-9.]+[^0-9]+([0-9]+)", string: strstr(db2ls_res, '/'));
if (!isnull(fp[1]))
  fix_pack = fp[1];

set_kb_item(name: "ibm/db2/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "ibm/db2/ssh-login/" + port + "/fix_pack", value: fix_pack);

exit(0);
