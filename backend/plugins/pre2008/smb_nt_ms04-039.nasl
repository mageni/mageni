# OpenVAS Vulnerability Test
# $Id: smb_nt_ms04-039.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)
#
# Authors:
# Noam Rathaus <noamr@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Jeff Adams
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
  script_oid("1.3.6.1.4.1.25623.1.0.15714");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-0892");
  script_name("ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"The ISA Server 2000 and Proxy Server 2.0 have been found to be vulnerable to
  a spoofing vulnerability that could enable an attacker to spoof trusted Internet
  content. Users could believe they are accessing trusted Internet content when
  in reality they are accessing malicious Internet content, for example a
  malicious Web site. However, an attacker would first have to persuade a user to
  visit the attacker's to attempt to exploit this vulnerability.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms04-039.mspx");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
if(!fix)security_message(port:0);
