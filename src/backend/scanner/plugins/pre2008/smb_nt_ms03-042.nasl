###############################################################################
# OpenVAS Vulnerability Test
#
# Buffer Overflow in Windows Troubleshooter ActiveX Control (826232)
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11887");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2003-0661");
  script_name("Buffer Overflow in Windows Troubleshooter ActiveX Control (826232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"A security vulnerability exists in the Microsoft Local Troubleshooter ActiveX control in
  Windows 2000.");

  script_tag(name:"insight", value:"The vulnerability exists because the ActiveX control (Tshoot.ocx) contains
  a buffer overflow.

  To exploit this vulnerability, the attacker would have to create a specially formed HTML based
  e-mail and send it to the user.

  Alternatively an attacker would have to host a malicious Web site that contained a Web page
  designed to exploit this vulnerability.");

  script_tag(name:"impact", value:"This flaw could allow an attacker to run code of their choice on a user's system.");
  script_tag(name:"affected", value:"Windows 2000");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms03-042.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(win2k:5) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB826232") > 0 )
  security_message(port:0);
