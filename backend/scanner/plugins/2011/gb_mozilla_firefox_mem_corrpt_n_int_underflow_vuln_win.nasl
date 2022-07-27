###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mem_corrpt_n_int_underflow_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Mozilla Firefox Memory Corruption and Integer Underflow Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802170");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-2996", "CVE-2011-2998");
  script_bugtraq_id(49845, 49809);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Memory Corruption and Integer Underflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  with the privileges of the user running the affected application. Failed
  attempts may trigger a denial-of-service condition.");
  script_tag(name:"affected", value:"Mozilla Firefox 3.6.x before 3.6.23");
  script_tag(name:"insight", value:"The flaws are due to

  - An integer underflow error exists within the Regular Expression engine
    when evaluating certain regular expressions.

  - An unspecified error can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.23 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox and is prone to memory
  corruption and integer underflow vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.22")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
