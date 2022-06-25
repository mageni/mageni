###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_oct10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Google Chrome multiple vulnerabilities - October 10(Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801473");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-4033", "CVE-2010-4035", "CVE-2010-4034", "CVE-2010-4036",
                "CVE-2010-4037", "CVE-2010-4038", "CVE-2010-4040", "CVE-2010-4042");
  script_bugtraq_id(44241);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - October 10(Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41888");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2731");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/10/stable-channel-update.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  in the context of the browser, cause denial-of-service conditions, carry out
  spoofing attacks, gain access to sensitive information, and bypass intended
  security restrictions.");
  script_tag(name:"affected", value:"Google Chrome version prior to 7.0.517.41");
  script_tag(name:"insight", value:"The flaws are due to

  - An unknown error related to 'autofill/autocomplete' profile spamming.

  - Memory corruption error when processing malformed forms, which could be
    exploited to execute arbitrary code.

  - A memory corruption error related to form 'autofill'.

  - An error when handling page unloads, which could allow URL spoofing attacks.

  - An unspecified error which could allow malicious web sites to bypass the
    pop-up blocker.

  - An error related to shutdown with 'Web Sockets'.

  - A memory corruption error when processing animated 'GIFs'.

  - Error in Stale elements in an element map.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 7.0.517.41 or later.");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"7.0.517.41")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
