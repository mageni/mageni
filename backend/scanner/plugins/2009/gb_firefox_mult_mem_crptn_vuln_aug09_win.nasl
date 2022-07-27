###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mult_mem_crptn_vuln_aug09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox Multiple Memory Corruption Vulnerabilities Aug-09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800855");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2654");
  script_bugtraq_id(35927, 35803);
  script_name("Mozilla Firefox Multiple Memory Corruption Vulnerabilities Aug-09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36001/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-44.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-45.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code, phishing
  attack, and can cause Denial of Service.");

  script_tag(name:"affected", value:"Firefox version before 3.0.13 or 3.5 before 3.5.2 on Windows.");

  script_tag(name:"insight", value:"Multiple memory corruption are due to:

  - Error in 'js_watch_set()' function in js/src/jsdbgapi.cpp in the JavaScript
    engine which can be exploited via a crafted '.js' file.

  - Error in 'libvorbis()' which is used in the application can be exploited
    via a crafted '.ogg' file.

  - Error in 'TraceRecorder::snapshot()' function in js/src/jstracer.cpp and
    other unspecified vectors.

  - Error in 'window.open()' which fails to sanitise the invalid character in
    the crafted URL. This allows remote attackers to spoof the address bar,
    and possibly conduct phishing attacks, via a crafted web page that calls
    window.open with an invalid character in the URL, makes document.write
    calls to the resulting object, and then calls the stop method during the
    loading of the error page.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.13/3.5.2.");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to multiple
  Memory Corruption vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.0.13")||
   version_in_range(version:ffVer, test_version:"3.5",
                                  test_version2:"3.5.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
