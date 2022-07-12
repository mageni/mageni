###############################################################################
# OpenVAS Vulnerability Test
#
# Buffer Overrun In HTML Converter Could Allow Code Execution (823559)
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11878");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8016);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0469");
  script_name("Buffer Overrun In HTML Converter Could Allow Code Execution (823559)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"There is a flaw in the way the HTML converter for Microsoft Windows handles a
  conversion request during a cut-and-paste operation. This flaw causes a security vulnerability to exist.");

  script_tag(name:"impact", value:"A specially crafted request to the HTML converter could cause the converter
  to fail in such a way that it could execute code in the context of the currently logged-in user. Because this
  functionality is used by Internet Explorer, an attacker could craft a specially formed Web page or HTML e-mail
  that would cause the HTML converter to run arbitrary code on a user's system. A user visiting an attacker's Web
  site could allow the attacker to exploit the vulnerability without any other user action.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms03-023.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823559") > 0 )
  security_message(port:0);
