###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_code_exec_vuln_nov12_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Mozilla Firefox Code Execution Vulnerabilities - November12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803062");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-4210");
  script_bugtraq_id(56646);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-26 15:52:10 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla Firefox Code Execution Vulnerabilities - November12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51358");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027791");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027792");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-104.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain privileges or execute
  arbitrary code in the context of the browser.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 17.0 on Mac OS X");
  script_tag(name:"insight", value:"An error within Style Inspector when parsing style sheets can be exploited
  to execute HTML and CSS code in chrome privileged context.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 17.0 or later.");
  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to multiple
  code execution vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"17.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
