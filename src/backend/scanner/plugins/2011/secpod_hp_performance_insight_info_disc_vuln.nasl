##############################################################################
# OpenVAS Vulnerability Test
#
# HP Performance Insight Remote Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902417");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-1536");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("HP Performance Insight Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_hp_performance_insight_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("hp_openview_insight/installed");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1060");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.bugtraq/46897");
  script_xref(name:"URL", value:"http://www.criticalwatch.com/support/security-advisories.aspx?AID=35689");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02790298");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to gain knowledge of sensitive
  information.");

  script_tag(name:"affected", value:"HP Performance Insight version 5.41.002 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by an unknown error which could be exploited remotely to
  access sensitive information.");

  script_tag(name:"summary", value:"This host is running HP Performance Insight and is prone to
  information disclosure vulnerability.");

  script_tag(name:"solution", value:"Upgrade to HP Performance Insight 5.41.002 and apply the
  HF04 / QCCR1B88272 hotfix.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);

if(vers = get_version_from_kb(port:port, app:"hp_openview_insight"))
{
  version =  eregmatch(pattern:"([0-9.]+)", string:vers);
  if(version[1])
  {
    if(version_is_less_equal(version:version[1], test_version:"5.41.002")){
      security_message(port);
    }
  }
}
