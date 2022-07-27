###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_iframe_dos_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Opera 'IFRAME' Denial Of Service vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801216");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2121");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Opera 'IFRAME' Denial Of Service vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded");
  script_xref(name:"URL", value:"http://websecurity.com.ua/4238/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Opera version 9.52");
  script_tag(name:"insight", value:"The flaw is due to improper handling of 'JavaScript' code which
  contains an infinite loop, that creates IFRAME elements for invalid news://
  or nntp:// URIs.");
  script_tag(name:"solution", value:"Upgrade to Opera Version 10 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera Browser and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/download/");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("Opera/Win/Version");

if(ver)
{
  if(version_is_equal(version:ver, test_version:"9.52")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
