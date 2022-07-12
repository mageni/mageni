###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_info_disc_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Products Information Disclosure Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900910");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-08-19 06:49:38 +0200 (Wed, 19 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-6961");
  script_bugtraq_id(32363);
  script_name("Mozilla Products Information Disclosure Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32714");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32715");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46734");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-59.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers obtain the mailbox URI of the
  recipient or disclose comments placed in a forwarded email.");

  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.13 and
  Thunderbird version prior to 2.0.0.18 on Windows.");

  script_tag(name:"insight", value:"A flaw exists in the JavaScript code embedded in mailnews which can be
  exploited using scripts which read the '.documentURI' or '.textContent' DOM properties.");

  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.13 or later

  Upgrade to Thunderbird version 2.0.0.18 or later.");

  script_tag(name:"summary", value:"The host is installed with Thunderbird/Seamonkey and is prone to
  Information Disclosure vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Win/Ver");

if(smVer != NULL)
{
  if(version_is_less(version:smVer, test_version:"1.1.13")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");

if(tbVer != NULL)
{
  if(version_is_less(version:tbVer, test_version:"2.0.0.18")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
