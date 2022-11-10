# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170204");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-28 12:56:06 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("UPnP Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("gb_upnp_udp_detect.nasl", "find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 52881);

  script_tag(name:"summary", value:"TCP-based detection of the UPnP protocol.

  The script sends a HTTP request to URLs for the root description XML, either based
  on previously detected location or a list of known possible locations.");

  script_xref(name:"URL", value:"https://openconnectivity.org/foundation/faq/upnp-faq/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("http_keepalive.inc");

function handleUPnPXML( xml, port ) {

  local_var port, xml;
  local_var extra;

  extra = NULL;

  #<device>
  #  <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
  #  <friendlyName>SR1217 (DS216se)</friendlyName>
  #  <manufacturer>Synology</manufacturer>
  #  <manufacturerURL>http://www.synology.com</manufacturerURL>
  #  <modelDescription>Synology NAS</modelDescription>
  #  <modelName>DS216se</modelName>
  #  <modelNumber>DS216se 6.2-25556</modelNumber>
  #  <modelURL>http://www.synology.com</modelURL>
  #  <modelType>NAS</modelType>
  #  <serialNumber>redacted</serialNumber>
  manufacturer = eregmatch( pattern:"<manufacturer>([^<]+)</manufacturer>", string:xml );
  model_name   = eregmatch( pattern:"<modelName>([^<]+)</modelName>", string:xml );
  model_number = eregmatch( pattern:"<modelNumber>([^<]+)</modelNumber>", string:xml );
  model_type = eregmatch( pattern:"<modelType>([^<]+)</modelType>", string:xml );
  model_description = eregmatch( pattern:"<modelDescription>([^<]+)</modelDescription>", string:xml );

  if ( ! isnull( manufacturer[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/manufacturer", value:manufacturer[1] );
    extra = "  Manufacturer: " + manufacturer[1];
  }
  if ( ! isnull( model_name[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelName", value:model_name[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Name:   " + model_name[1];
  }
  if ( ! isnull( model_number[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelNumber", value:model_number[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Number: " + model_number[1];
  }
  if ( ! isnull( model_type[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelType", value:model_type[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Type:   " + model_type[1];
  }
  if ( ! isnull( model_description[1] ) )
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelDescription", value:model_description[1] );
  # nb: Save the full XML to be used by client detections
  set_kb_item( name:"upnp/tcp/" + port + "/device/full_xml", value:xml );

  return extra;
}

report = "";
port = 0;

if ( location = get_kb_item( "upnp/location" ) ) {
  # eg. LOCATION: http://<redacted>:<redacted>/ssdp/desc-DSM-eth0.xml
  # nb: The part after http(s):// is always an IP, so this can be simplified
  loc = eregmatch( pattern:"LOCATION:\s*https?://[0-9.]+:([0-9]+)(/[-a-zA-Z0-9_/]+\.(xml|jsp))", string:location, icase:TRUE );

  if ( ! isnull( loc[2] ) ) {
    res = http_get_cache( item:loc[2], port:loc[1] );

    if ( ! isnull( res ) && res =~ "^HTTP/(1\.[01]|2) 200" ) {
      port = loc[1];
      extra = handleUPnPXML( xml:res, port:port );
      set_kb_item( name:"upnp/tcp/" + loc[1] + "/location", value:loc[2] );

      report  = "The remote Host exposes an uPnP root device XML on port " + port + '/tcp.\n';
      report += '\nThe XML can be found at the location:\n  ' + loc[2];
      if ( ! isnull( extra ) )
        report += '\n\nExcerpt from the obtained data:\n' + extra;
    }
  }
} else {
  xml_locations = make_list( "/simplecfg.xml",
                             "/rootDesc.xml",
                             "/devdescr.xml",
                             "/gateway.xml",
                             "/devicedesc.xml",
                             "/description.xml",
                             "/ssdp/device-desc.xml",
                             "/XD/DeviceDescription.xml",
                             "/DeviceDescription.xml",
                             "/device-desc.xml",
                             "/IGD.xml",
                             "/ssdp/desc-DSM-eth0.xml",
                             "/ssdp/desc-DSM-eth1.xml",
                             "/ssdp/desc-DSM-bond0.xml",
                             "/etc/linuxigd/gatedesc.xml",
                             "/upnp/descr.xml",
                             "/upnp/BasicDevice.xml",
                             "/cameradesc.xml",
                             "/bmlinks/ddf.xml",
                             "/picsdesc.xml",
                             "/rss/Starter_desc.xml",
                             "/DSDeviceDescription.xml",
                             "/upnpdevicedesc.xml",
                             "/ssdp/desc-DSM-eth1.4000.xml",
                             "/ssdp/desc-DSM-ovs_eth0.xml",
                             "/upnp.jsp",
                             "/wps_device.xml",
                             "/desc/root.cs",
                             "/MediaServerDevDesc.xml",
                             "/UPnP/IGD.xml" );

  # nb: The TCP port depends on the vendor, currently the most commonly found port (Realtek) is used as a default
  port = http_get_port( default:52881 );

  foreach location( xml_locations ) {

    res = http_get_cache( item:location, port:port );

    if ( ! isnull( res ) && res =~ "^HTTP/(1\.[01]|2) 200" ) {
      extra = handleUPnPXML( xml:res, port:port );
      set_kb_item( name:"upnp/tcp/" + port + "/location", value:location );

      report  = "The remote Host exposes an uPnP root device XML on port " + port + '/tcp.\n';
      report += '\nThe XML can be found at the location:\n  ' + location;
      if ( ! isnull( extra ) )
        report += '\n\nExcerpt from the obtained data:\n' + extra;

      break;
    }
  }
}

if ( report && port ) {
  service_register( port:port, ipproto:"tcp", proto:"upnp", message:report );
  log_message( data:report, port:port, proto:"tcp" );
}

exit( 0 );
