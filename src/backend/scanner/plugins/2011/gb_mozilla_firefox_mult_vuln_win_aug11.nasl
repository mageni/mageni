###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_win_aug11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Mozilla Firefox Multiple Vulnerabilities August-11 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802138");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-2008-7293");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Mozilla Firefox Multiple Vulnerabilities August-11 (Windows)");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2008/11/cookie-forcing.html");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2011/02/some-less-obvious-benefits-of-hsts.html");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to overwrite or delete
  arbitrary cookies via a Set-Cookie header in an HTTP response, which results
  into cross site scripting, cross site request forgery and denial of service
  attacks.");
  script_tag(name:"affected", value:"Mozilla Firefox versions before 4.0");
  script_tag(name:"insight", value:"Multiple flaws are due to not properly restricting modifications to
  cookies established in HTTPS sessions.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 4.0 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"4.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
