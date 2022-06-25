Required tools:

To execute the Report Format plugin properly,
the special tools "shp2img" of the UMN MapServer project
and "ogr2ogr" of the GDAL project are required to be available
for the environment where gvmd is running.

Mapping IPs:

This simple map report generator uses
a static list of georeferenced IPs
in the file "locations.csv".
You need to extend this file for your network for
a respective map.

Origin of background map:

VMAP0 is a public domain data set (http://en.wikipedia.org/wiki/Vector_Map)
and can be downloaded and processed e.g. this way:

curl "http://vmap0.tiles.osgeo.org/wms/vmap0?LAYERS=basic&SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&STYLES=&EXCEPTIONS=application%2Fvnd.ogc.se_inimage&FORMAT=image%2Fpng&SRS=EPSG%3A4326&BBOX=-180,-90,180,90&WIDTH=2000&HEIGHT=1000" > world_map.png

gdal_translate -of gtiff -co "compress=LZW" -a_ullr 90 -180 -90 180 -a_srs "wgs84" world_map.png world_map.tiff
