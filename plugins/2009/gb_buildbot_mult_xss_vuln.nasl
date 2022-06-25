###############################################################################
# OpenVAS Vulnerability Test
#
# Buildbot Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800935");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2967");
  script_bugtraq_id(36100);
  script_name("Buildbot Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36352");
  script_xref(name:"URL", value:"http://buildbot.net/trac#SecurityAlert");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2352");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_buildbot_detect.nasl");
  script_mandatory_keys("Buildbot/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject arbitrary web script
  or HTML via unspecified vectors and conduct cross-site scripting attacks.");
  script_tag(name:"affected", value:"Buildbot version 0.7.6 through 0.7.11p2 on all platforms.");
  script_tag(name:"insight", value:"Several scripts in the application do not adequately sanitise user supplied
  data before processing and returning it to the user.");
  script_tag(name:"summary", value:"This host is installed with Buildbot and is prone to multiple
  Cross Site Scripting vulnerabilities.");
  script_tag(name:"solution", value:"Apply the patches or upgrade to version 0.7.11p3.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

buildbotVer = get_kb_item("Buildbot/Ver");
if(!buildbotVer)
  exit(0);

if(version_in_range(version:buildbotVer, test_version:"0.7.6", test_version2:"0.7.11.p2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
