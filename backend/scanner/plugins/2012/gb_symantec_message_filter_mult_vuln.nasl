###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_message_filter_mult_vuln.nasl 11020 2018-08-17 07:35:00Z cfischer $
#
# Symantec Message Filter Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103501");
  script_bugtraq_id(54136, 54135, 54134, 54133);
  script_cve_id("CVE-2012-0300", "CVE-2012-0301", "CVE-2012-0302", "CVE-2012-0303");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11020 $");

  script_name("Symantec Message Filter Multiple Vulnerabilities");


  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:35:00 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-06-27 12:18:39 +0200 (Wed, 27 Jun 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"The vendor has released an advisory and fixes. Please see the
references for more information.");
  script_tag(name:"summary", value:"Symantec Message Filter is prone to multiple vulnerabilities.

1. A remote information-disclosure vulnerability.

Attackers can exploit this issue to gain access to sensitive
information that may aid in further attacks.

2. A session-fixation vulnerability.

Successfully exploiting this issue, an attacker can hijack an arbitrary session
and gain unauthorized access to the affected application.

3. An unspecified cross-site scripting vulnerability because it fails to
sufficiently sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code in the
browser of an unsuspecting user in the context of the affected site. This may
allow the attacker to steal cookie-based authentication credentials and to
launch other attacks.

4. An unspecified cross-site request-forgery vulnerability.

Exploiting this issue may allow a remote attacker to perform certain
administrative actions and gain unauthorized access to the affected application.
Other attacks are also possible.

Symantec Message Filter 6.3 is vulnerable.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54136");
  script_xref(name:"URL", value:"http://www.symantec.com");
  script_xref(name:"URL", value:"http://www.symantec.com/business/support/index?page=content&id=TECH191487");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = '/brightmail/index.jsp';

if(http_vuln_check(port:port, url:url, pattern:"<title>Symantec.*Message Filter.*login</title>", usecache:TRUE)) {

  url = '/brightmail/about.jsp';

  # http://www.symantec.com/business/support/index?page=content&id=TECH191487
  #
  # Verification
  #
  # ============
  #
  # Open a new browser, and type the following URL's one at a time:
  #
  #  1. http://<your_ControlCenter_IP>:41080/brightmail/about.jsp
  #  2. http://<your_ControlCenter_IP>:41080/brightmail/try.do
  #
  #  Expected results:
  #
  #   1. You are redirected to the user logon page.
  #   2. An error page with Symantec logo is displayed indicating "Bad Request".

  if(http_vuln_check(port:port, url:url,pattern:"About Symantec",extra_check:make_list("iframe.*legal.html"),check_header:TRUE)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
