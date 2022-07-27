###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_xss_vuln_sep09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Opera Multiple Cross-Site Scripting Vulnerabilities - Sep09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900857");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3265", "CVE-2009-3266");
  script_bugtraq_id(36418);
  script_name("Opera Multiple Cross-Site Scripting Vulnerabilities - Sep09 (Windows)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/506517/100/0/threaded");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/09/exploiting-chrome-and-operas-inbuilt-atomrss-reader-with-script-execution-and-more/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Attacker can exploit this issue to conduct XSS attacks to inject
arbitrary web script or HTML.");
  script_tag(name:"affected", value:"Opera version 9.x and 10.x on Windows.");
  script_tag(name:"insight", value:"An error in the application which can be exploited to obtain
complete control over feeds via a 'RSS' or 'Atom' feed. It is related to the
rendering of the application/rss+xml content type as 'scripted content'.");
  script_tag(name:"solution", value:"Upgrade to version 10.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Opera and is prone to multiple
Cross-Site Scripting vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(operaVer =~ "^(9|10)\..*"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
