###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_insight_diag_xss_vuln_lin.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# HP SMH Insight Diagnostics Cross Site Scripting Vulnerability - Linux
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800191");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4111");
  script_name("HP SMH Insight Diagnostics Cross Site Scripting Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129245189832672&w=2");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024897.html");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02652463");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary HTML code
  in the context of an affected site.");

  script_tag(name:"affected", value:"HP Insight Diagnostics Online Edition before 8.5.1.3712 on Linux.");

  script_tag(name:"insight", value:"The flaw is caused due imporper validation of user supplied input via
  unspecified vectors, which allows attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an
  affected site.");

  script_tag(name:"solution", value:"Upgrade to 8.5.1.3712 or higher versions or refer vendor advisory for update.");

  script_tag(name:"summary", value:"The host is running HP SMH with Insight Diagnostics and is prone
  to cross-site scripting vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

rpm_cmd = "rpm -qa --qf '%{VERSION}.%{RELEASE}\n' hpdiags";
hpdiag_ver = ssh_cmd( socket:sock, cmd:rpm_cmd, timeout:120 );

if( ! hpdiag_ver || "rpm:" >< hpdiag_ver || "not found" >< hpdiag_ver ) {
  exit( 0 );
}

if( hpdiag_ver =~ "^[0-8]\." ) {
  if( version_is_less( version:hpdiag_ver, test_version:"8.5.1.3712" ) ) {
    report = report_fixed_ver( installed_version:hpdiag_ver, fixed_version:"8.5.1.3712" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
