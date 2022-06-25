###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dcetest_report.nasl 6319 2017-06-13 07:06:12Z cfischer $
#
# DCE/RPC and MSRPC Services Enumeration Reporting
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.10736");
  script_version("$Revision: 6319 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-13 09:06:12 +0200 (Tue, 13 Jun 2017) $");
  script_tag(name:"creation_date", value:"2017-01-12 15:08:04 +0100 (Thu, 12 Jan 2017)");
  script_name("DCE/RPC and MSRPC Services Enumeration Reporting");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("dcetest.nasl");
  script_require_ports("Services/epmap", 135);
  script_mandatory_keys("dcetest/enumerated");
  script_add_preference(name:"Report local DCE services", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"Distributed Computing Environment / Remote Procedure Calls (DCE/RPC) or MSRPC services running
  on the remote host can be enumerated by connecting on port 135 and doing the appropriate queries.");

  script_tag(name:"impact", value:"An attacker may use this fact to gain more knowledge
  about the remote host.");

  script_tag(name:"solution", value:"Filter incoming traffic to this ports.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/epmap" );
if( ! port ) port = 135;

if( ! get_kb_item( "dcetest/" + port + "/enumerated" ) ) exit( 0 );

all_tcp_ports = get_kb_list( "dcetest/" + port + "/enumerated/tcp/ports" );

if( ! isnull( all_tcp_ports ) ) {

  report += 'Here is the list of DCE/RPC or MSRPC services running on this host via the TCP protocol:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  all_tcp_ports = sort( all_tcp_ports );

  foreach tcp_port( all_tcp_ports ) {

    tcp_reports = get_kb_list( "dcetest/" + port + "/enumerated/tcp/" + tcp_port + "/report" );

    if( ! isnull( tcp_reports ) ) {

      service_report = 'The following DCE/RPC or MSRPC services are running on this port:\n\n';
      report += "Port: " +  tcp_port + '/tcp\n\n';
      # Sort to not report changes on delta reports if just the order is different
      tcp_reports = sort( tcp_reports );

      foreach tcp_report( tcp_reports ) {
        report += tcp_report + '\n';
        service_report += tcp_report + '\n';
      }

      if( get_port_state( tcp_port ) )
        log_message( port:tcp_port, proto:"tcp", data:service_report );
    }
  }
}

all_udp_ports = get_kb_list( "dcetest/" + port + "/enumerated/udp/ports" );

if( ! isnull( all_udp_ports ) ) {

  report += 'Here is the list of DCE/RPC or MSRPC services running on this host via the UDP protocol:\n\n';

  # Sort to not report changes on delta reports if just the order is different
  all_udp_ports = sort( all_udp_ports );

  foreach udp_port( all_udp_ports ) {

    udp_reports = get_kb_list( "dcetest/" + port + "/enumerated/udp/" + udp_port + "/report" );

    if( ! isnull( udp_reports ) ) {

      service_report = 'The following DCE/RPC or MSRPC services are running on this port:\n\n';
      report += "Port: " +  udp_port + '/udp\n\n';
      # Sort to not report changes on delta reports if just the order is different
      udp_reports = sort( udp_reports );

      foreach udp_report( udp_reports ) {
        report += udp_report + '\n';
        service_report += tcp_report + '\n';
      }

      if( get_udp_port_state( udp_port ) )
        log_message( port:udp_port, proto:"udp", data:service_report );
    }
  }
}

noport_reports = get_kb_list( "dcetest/" + port + "/enumerated/noport/report" );

if( ! isnull( noport_reports ) ) {

  reportLocal = script_get_preference( "Report local DCE services" );

  if( reportLocal == "yes" ) {

    report += 'Here is the list of DCE/RPC or MSRPC services running on this host locally:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    noport_reports = sort( noport_reports );

    foreach noport_report( noport_reports ) {
      report += noport_report + '\n';
    }
  } else {
    report += "Note: DCE/RPC or MSRPC services running on this host locally were identified. ";
    report += "Reporting this list is not enabled by default due to the possible large size of this list. ";
    report += "See the script preferences to enable this reporting.";
  }
}

security_message( port:port, data:report );

exit( 0 );
