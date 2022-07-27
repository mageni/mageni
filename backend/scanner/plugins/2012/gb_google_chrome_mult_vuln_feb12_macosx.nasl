###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_feb12_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - February 12 (MAC OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802596");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-3960", "CVE-2011-3959", "CVE-2011-3958", "CVE-2011-3957",
                "CVE-2011-3972", "CVE-2011-3956", "CVE-2011-3971", "CVE-2011-3955",
                "CVE-2011-3970", "CVE-2011-3954", "CVE-2011-3969", "CVE-2011-3953",
                "CVE-2011-3968", "CVE-2011-3967", "CVE-2011-3966", "CVE-2011-3965",
                "CVE-2011-3964", "CVE-2011-3963", "CVE-2011-3962", "CVE-2011-3961");
  script_bugtraq_id(51911);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-14 17:13:43 +0530 (Tue, 14 Feb 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - February 12 (MAC OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47938/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026654");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/02/stable-channel-update.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.46 on MAC OS X");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17.0.963.46 or later.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(isnull(chromeVer)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"17.0.963.46")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
