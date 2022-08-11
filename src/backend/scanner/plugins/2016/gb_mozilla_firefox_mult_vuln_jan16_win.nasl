###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_jan16_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Mozilla Firefox Multiple Vulnerabilities - Jan16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807054");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935",
                "CVE-2016-1939", "CVE-2015-7208", "CVE-2016-1937", "CVE-2016-1938",
                "CVE-2016-1943", "CVE-2016-1942", "CVE-2016-1944", "CVE-2016-1945",
                "CVE-2016-1946", "CVE-2016-1978");
  script_bugtraq_id(79280);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-29 09:21:18 +0530 (Fri, 29 Jan 2016)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - Jan16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory-corruption vulnerabilities.

  - An error in the image parsing code during the de-interlacing of a
    maliciously crafted GIF formatted image resulting in a possible integer
    overflow.

  - A buffer-overflow vulnerability.

  - A security-bypass vulnerability, that allows for control characters to be
    set in cookie names.

  - A lack of delay following user click events in the protocol handler dialog,
    resulting in double click events to be treated as two single click events.

  - Calculations with mp_div and mp_exptmod in Network Security Services (NSS)
    can produce wrong results in some circumstances, leading to potential
    cryptographic weaknesses.

  - Multiple security-bypass vulnerability exists for address bar spoofing
    attacks, that can lead to potential spoofing.

  - A Use-after-free vulnerability in the 'ssl3_HandleECDHServerKeyExchange'
    function.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to bypass security restrictions and perform unauthorized actions,
  obtain sensitive information, bypass same-origin policy restrictions to
  access data, and execute arbitrary code in the context of the affected
  application. Failed exploit attempts will likely result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 44 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 44
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories");
  script_xref(name:"URL", value:"http://msisac.cisecurity.org/advisories/2016/2016-018.cfm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"44.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"44.0");
  security_message(data:report);
  exit(0);
}