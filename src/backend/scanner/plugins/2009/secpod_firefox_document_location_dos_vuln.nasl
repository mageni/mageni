###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_document_location_dos_vuln.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox 'document.location' Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900831");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-08-28 14:39:11 +0200 (Fri, 28 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2975");
  script_name("Mozilla Firefox 'document.location' Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0246.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0234.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-08/0236.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause excessive memory
  consumption in the affected application and results in Denial of Service
  condition.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.2 on Windows XP.");
  script_tag(name:"insight", value:"The flaw is due to an incompletely configured protocol handler that does not
  properly implement setting of the 'document.location' property to a value
  specifying a protocol associated with an external application, which can
  be caused via vectors involving a series of function calls that set this
  property, as demonstrated by the 'chromehtml:' and 'aim:' protocols.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"The host is installed with Firefox browser on Windows XP and is
  prone to Denial of Service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

ffVer = get_kb_item("Firefox/Win/Ver");

if(isnull(ffVer))
{
  exit(0);
}

if(version_is_equal(version:ffVer, test_version:"3.5.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
