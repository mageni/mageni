###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_jun13_lin.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 June13 (Linux)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803648");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-2865", "CVE-2013-2864", "CVE-2013-2863", "CVE-2013-2862",
                "CVE-2013-2861", "CVE-2013-2860", "CVE-2013-2859", "CVE-2013-2858",
                "CVE-2013-2857", "CVE-2013-2856", "CVE-2013-2855", "CVE-2013-2854");
  script_bugtraq_id(60395, 60396, 60397, 60398, 60399, 60400, 60401, 60402, 60403,
                    60404, 60405, 60406);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-11 15:37:34 +0530 (Tue, 11 Jun 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 June13 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53681");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53681");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/06/stable-channel-update.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  bypass security restrictions, corrupt memory, or cause denial of service
  conditions.");
  script_tag(name:"affected", value:"Google Chrome version prior to 27.0.1453.110 on Linux");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Use-after-free errors in input handling, image handling, HTML5 Audio, SVG,
    and when accessing database APIs.

  - Unspecified erros with dev tools API, Skia GPU handling, SSL socket
    handling, and PDF viewer.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 27.0.1453.110 or later.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"27.0.1453.110"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
