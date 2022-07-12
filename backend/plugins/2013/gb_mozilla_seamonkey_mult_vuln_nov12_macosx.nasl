###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_seamonkey_mult_vuln_nov12_macosx.nasl 11887 2018-10-12 13:53:37Z cfischer $
#
# Mozilla Seamonkey Multiple Vulnerabilities - November12 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803634");
  script_version("$Revision: 11887 $");
  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_bugtraq_id(56301, 56302, 56306);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:53:37 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-02 16:08:12 +0530 (Fri, 02 Nov 2012)");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities - November12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51144");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027703");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-90.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject scripts and bypass
  certain security restrictions.");
  script_tag(name:"affected", value:"Mozilla SeaMonkey version before 2.13.2 on Mac OS X");
  script_tag(name:"insight", value:"Multiple errors

  - When handling the 'window.location' object.

  - Within CheckURL() function of the 'window.location' object, which can be
    forced to return the wrong calling document and principal.

  - Within handling of 'Location' object can be exploited to bypass security
    wrapper protection.");
  script_tag(name:"solution", value:"Upgrade to Mozilla SeaMonkey version to 2.13.2 or later.");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey");
  script_tag(name:"summary", value:"This host is installed with Mozilla Seamonkey and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.13.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
