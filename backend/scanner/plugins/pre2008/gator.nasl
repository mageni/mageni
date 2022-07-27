# OpenVAS Vulnerability Test
# $Id: gator.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Gator/GAIN Spyware Installed
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
#
# Copyright:
# Copyright (C) 2003 Jeff Adams
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11883");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gator/GAIN Spyware Installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Jeff Adams");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Uninstall the software");

  script_tag(name:"summary", value:"The remote host has Gator/GAIN Spyware Installed. Gator tracks the sites that
  users visit and forwards that data back to the company's servers. Gator sells
  the use of this information to advertisers. It also lets companies launch a
  pop-up ad when users visit various Web sites. This software is not suitable
  for a business environment.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

rootfile = registry_get_sz(key:"SOFTWARE\Gator.com\Gator\dyn", item:"AppExe");
if(rootfile)
{
 security_message(get_kb_item("SMB/transport"));
}
