###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sitescope_xss_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

CPE = "cpe:/a:hp:sitescope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801881");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-1726", "CVE-2011-1727");
  script_bugtraq_id(47554);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_sitescope_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("hp/sitescope/installed");

  script_xref(name:"URL", value:"https://secunia.com/advisories/44354");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45958");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1091");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02807712");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker-supplied HTML and script code
  to run in the context of the affected browser, potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the user. Other attacks are also possible.");

  script_tag(name:"affected", value:"HP SiteScope versions 9.54, 10.13, 11.01, and 11.1");

  script_tag(name:"insight", value:"The flaws are caused by input validation errors when processing
  user-supplied data, which could allow cross site scripting or HTML injection attacks.");

  script_tag(name:"solution", value:"Upgrade to HP SiteScope version 11.1 and apply the SS1110110412 hotfix.");

  script_tag(name:"summary", value:"This host is running HP SiteScope and is prone to cross site scripting
  and HTML injection vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = string("/SiteScope/jsp/hosted/HostedSiteScopeMessage.jsp?messageKey=",
              "<script>alert('openvas-xss-test')</script>");

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"en.<script>alert\('openvas-xss-test'\)</script>"))
{
  security_message(port);
  exit(0);
}

exit(0);
