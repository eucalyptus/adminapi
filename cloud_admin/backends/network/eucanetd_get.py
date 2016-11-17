
from cloud_utils.log_utils import get_traceback
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.system_utils.machine import Machine
from xml.dom import minidom
from xml.etree.ElementTree import Element
import xml.etree.ElementTree as ElementTree
from prettytable import PrettyTable
from os import path


tag_element_map = {}


class BaseElement(object):
    def __init__(self, xml_element, eucanetd=None):

        if xml_element is not None and not isinstance(xml_element, Element):
            raise ValueError('xml_element must be of type: {0}.{1}'.format(Element.__module__,
                                                                           Element.__name__))
        self._xml = xml_element
        self._eucanetd = eucanetd
        self._tag = None
        self._name = None
        self._log = Eulogger("{0}:{1}:{2}".format(self.__class__.__name__,
                                                  self.tag or "",
                                                  self.name or ""))
        self._update_from_xml(xml=self._xml)

    def _update(self):
        raise NotImplementedError('update not implemented for this class:{0}'
                                  .format(self.__class__.__name))

    def __repr__(self):
        try:
            attrs = [self.__class__.__name__]
            if self.tag:
                attrs.append(str(self.tag))
            if self.name:
                attrs.append(str(self.name))
            return ":".join(attrs)
        except Exception as E:
            print '{0}\nFailed to create repr, err:{1}'.format(get_traceback(), E)
            self.log.error('{0}\nFailed to create repr, err:{1}'.format(get_traceback(), E))

    def show(self, printme=True, printmethod=None):
        val_len = 70
        key_len = 30
        pt = PrettyTable(['key', 'value'])
        pt.align = 'l'
        pt.max_width['key'] = key_len
        pt.max_width['value'] = val_len
        pt.header = False
        pt.border = False
        pt.add_row(['tag', self.tag])
        pt.add_row(['name', self.name])
        for key, value in self.__dict__.iteritems():
            if not str(key).startswith('_'):
                if not isinstance(value, list):
                    pt.add_row([key, str(value)])
                else:
                    buf = ""
                    max = (val_len) / (len(str(value[0])) + 2)
                    count = 0
                    for v in value:
                        count += 1
                        buf += "{0},".format(v)
                        if not count % max:
                            buf += "\n"
                        else:
                            buf += " "
                    buf.strip(',')
                    pt.add_row([key, buf])


        if printme:
            printmethod = printmethod or self.log.info
            printmethod("\n{0}".format(pt))
        else:
            return pt

    @property
    def xml(self):
        return getattr(self, '__xml', None)

    @xml.setter
    def xml(self, xml):
        if xml != self.xml:
            self._xml = xml
            self._update_from_xml(xml=self._xml)

    @property
    def tag(self):
        try:
            if getattr(self, '__tag', None) is None:
                if getattr(self, '__xml', None) is not None:
                    self._tag = self.xml.tag
            return self._tag
        except Exception as E:
            print '{0}\nFailed to fetch tag, err:{1}'.format(get_traceback(), E)
            self.log.error('{0}\nFailed to fetch tag, err:{1}'.format(get_traceback(), E))

    @tag.setter
    def tag(self, tag):
        if tag != self.tag:
            self._tag = tag
            self._log = Eulogger("{0}:{1}:{2}".format(self.__class__.__name__,
                                                      self.tag or "",
                                                      self.name or ""))

    @property
    def log(self):
        return self._log

    @property
    def name(self):
        try:
            if getattr(self, '__name', None) is None:
                if self.xml is not None:
                    if 'name' in self.xml.attrib:
                        self._name =  self.xml.attrib.get('name')
            return self._name
        except Exception as E:
            print '{0}\nFailed to fetch name, err:{1}'.format(get_traceback(), E)
            self.log.error('{0}\nFailed to fetch name, err:{1}'.format(get_traceback(), E))

    @name.setter
    def name(self, name):
        if name != self.name:
            self._name = name
            self._log = Eulogger("{0}:{1}:{2}".format(self.__class__.__name__,
                                                      self.tag or "",
                                                      self.name or ""))

    def _update_from_xml(self, xml):
        attrs = vars(self).keys()
        for var in attrs:
            if not var.startswith('_'):
                self.__delattr__(var)
        self._set_defaults()
        if xml is not None:
            self.tag = xml.tag
            self._parse(xml=xml)
        self._xml = xml

    def _set_defaults(self):
        # Method to set default values of any attributes prior to parsing xml
        pass

    def _get_class_by_tag(self, tag):
        if tag in tag_element_map:
            return tag_element_map.get(tag)
        else:
            return BaseElement

    def _is_element_list(self, xml):
        # todo replace this guess work with populated tag_element_map
        if len(xml) > 1:
            for child in xml:
                if len(xml.findall(child.tag)) > 1:
                    return True
                else:
                    return False
        elif xml.text:
            return False
        elif hasattr(self, xml.tag):
            # If this attribute exists, possibly set by defaults check it's type
            return isinstance(getattr(self, xml.tag), list)
        elif str(xml.tag).endswith('s'):
            # There's not enough info available so guess based on the name :-(
            return True


    def _parse(self, xml):
        if not isinstance(xml, Element):
            raise ValueError('parse expected Element type for xml, got:{0}, type:{1}'
                             .format(xml, type(xml)))
        # Set attrs from xml attrib dict...
        for attr, value in xml.attrib.iteritems():
            try:
                setattr(self, attr, value)
            except Exception as E:
                self.log.error('Failed to set attr:{0}, value:{1} for obj:{2}'
                               .format(attr, value, self))
                raise E
        if self._is_element_list(xml):
            self.log.debug('We think: "{0}" is a list...'.format(xml.tag))
            new_list = []
            sub_child = None
            for sub_child in xml:
                tag = sub_child.tag
                tag_class = self._get_class_by_tag(tag)
                newobj = tag_class(xml_element=sub_child)
                new_list.append(newobj)
            self.log.debug('Setting {0} as a list to {1} with {2} length'
                           .format(sub_child.tag, self.tag, len(new_list)))
            return new_list
        else:
            for child in xml:
                if not child.tag:
                    self._log.warning('No tag for element:"{0}"'.format(child.__dict__))
                else:
                    if not len(child):
                        # No additional children so this is the final attribute
                        setattr(self, child.tag, child.text)
                    else:
                        self.log.debug('We think: "{0}" is a list, child:{1}...'.format(xml.tag,
                                                                                        child.tag))
                        tag_class = self._get_class_by_tag(child.tag)
                        newobj = tag_class(None)._parse(child)
                        setattr(self, child.tag, newobj)
            return self

class GlobalXML(BaseElement):

    def set_defaults(self):
        self.root = None
        self.instances = []
        self.security_groups = []
        self.vpcs = []

    def update(self):
        xml = self._eucanetd._get_global_xml_root()
        self._update_from_xml(xml=xml)


class EucanetdGet(object):

    def __init__(self, host=None, password=None, keypath=None, sshconnection=None, machine=None,
                 eucalyptus_run_path='/var/run/eucalyptus'):
        if (machine and (sshconnection or host)) or sshconnection and host:
            warning = 'Duplicate and or possibly conflicting machine connection info provided:' \
                      'host:{0}, sshconnection:{1}, machine:{2}'.format(host, sshconnection,
                                                                        machine)
        else:
            warning = ""
        if machine:
            sshconnection = machine.ssh

        if sshconnection:
            host = host or sshconnection.host
            password = password or sshconnection.password
            keypath = sshconnection or sshconnection.keypair
        if host:
            if not machine:
                machine = Machine(hostname=host, password=password, keypath=keypath,
                                  sshconnection=sshconnection)
        host = host or "unknown"
        self.log = Eulogger("{0}.{1}".format(self.__class__.__name__, host))
        if not host:
            self.log.warning('Connection info not provided for: {0}.init()'
                             .format(self.__class__.__name__))

        self.host = host
        self.password = password
        self.keypath = keypath
        self._machine = machine
        self._global_xml_path = None
        self._global_xml = None
        self.eucalyptus_run_path = eucalyptus_run_path or ""
        self.eucanetd_pid_file = path.join(self.eucalyptus_run_path,
                                           'eucanetd.pid')
        self.global_xml_version = path.join(self.eucalyptus_run_path,
                                            'global_network_info.version')

    @property
    def machine(self):
        if not self._machine:
            try:
                if self.host:
                    self._machine = Machine(hostname=self.host, password=self.password,
                                            keypath=self.keypath)
            except Exception as E:
                self.log.warning('{0}\nFailed to create machine object to host:"{1}", error:"{2}"'
                                 .format(get_traceback(), self.host, E))
        return self._machine

    @machine.setter
    def machine(self, machine):
        if machine is None or isinstance(machine, Machine):
            self._machine = machine
        else:
            self.log.error('In correct machine type provided: "{0} {1}"'.format(machine,
                                                                                type(machine)))


    ##############################################################################################
    #                                  Global XML methods
    ##############################################################################################

    @property
    def global_xml(self):
        try:
            if not self._global_xml:
                self._global_xml = GlobalXML(xml_element=self._get_global_xml_root())
            return self._global_xml
        except Exception as E:
            self.log.error("{0}\nFailed to create global xml element. Error:{1}"
                           .format(get_traceback(), E))

    @global_xml.setter
    def global_xml(self, global_xml):
        if global_xml is not None and not isinstance(global_xml, GlobalXML):
            raise ValueError('Global xml must be of type:{0} or None'.format(GlobalXML.__name__))

    @property
    def global_xml_path(self):
        # Since this file name may be different in different releases...
        if not self._global_xml_path:
            for fname in ['eucanetd_global_network_info.xml', 'global_network_info.xml']:
                fpath = path.join(self.eucalyptus_run_path, fname)
                if self.machine.is_file(fpath):
                    self._global_xml_path = fpath
                    break
                self._global_xml_path = None
        return self._global_xml_path

    def _get_global_xml_string(self, path=None):
        path = path or self.global_xml_path
        out = self.machine.sys('cat {0}'.format(path), listformat=False)
        return out

    def show_global_xml(self, path=None, indent=4, printmethod=None, printme=True):
        i_space = ""
        indent = indent or 0
        for x in xrange(0, indent):
            i_space += " "
        indent = i_space
        xml_str = self._get_global_xml_string(path=path)
        xml = minidom.parseString(xml_str)
        if printme:
            printmethod = printmethod or self.log.info
            printmethod("\n{0}".format(xml.toprettyxml(indent=indent)))
        else:
            return xml.toprettyxml(indent=indent)

    def _get_global_xml_root(self, path=None):
        path = path or self.global_xml_path
        xml = ElementTree.fromstring(self._get_global_xml_string(path=path))
        return xml
