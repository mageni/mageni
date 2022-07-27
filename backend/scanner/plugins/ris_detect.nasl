###############################################################################
# OpenVAS Vulnerability Test
#
# RIS (Remote Installation Service) Detection (Windows SMB Login)
#
# Authors:
# Jeff Adams <jadams@netcentrics.com>
#
# Copyright:
# Copyright (C) 2005 Jorge Pinto And Nelson Gomes
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12231");
  script_version("2021-03-18T13:55:00+0000");
  script_tag(name:"last_modification", value:"2021-03-19 11:21:45 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RIS (Remote Installation Service) Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Jorge Pinto And Nelson Gomes");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of RIS (Remote Installation
  Service).");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

port = kb_smb_transport();
if(!port)port = 139;

#---------------------------------
# My Main
#---------------------------------

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "SourcePath";
value = registry_get_sz(key:key, item:item);

if(!value) {
  exit(0);
}

if( match(string:value, pattern:'*RemInst*')  ){
  report = "The remote host was installed using RIS (Remote Installation Service).";
  log_message(port:port, data:report);
  exit(0);
}

exit(0);
