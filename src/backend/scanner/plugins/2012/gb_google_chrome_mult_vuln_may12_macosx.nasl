###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - May 12 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802793");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2011-3100", "CVE-2011-3084", "CVE-2011-3099", "CVE-2011-3083",
                "CVE-2011-3097", "CVE-2011-3095", "CVE-2011-3094", "CVE-2011-3093",
                "CVE-2011-3092", "CVE-2011-3091", "CVE-2011-3090", "CVE-2011-3089",
                "CVE-2011-3088", "CVE-2011-3087", "CVE-2011-3086", "CVE-2011-3085",
                "CVE-2011-3102");
  script_bugtraq_id(53540);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-05-17 12:28:09 +0530 (Thu, 17 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - May 12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49194/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027067");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/05/stable-channel-update.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 19.0.1084.46 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 19.0.1084.46 or later.");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"19.0.1084.46")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
