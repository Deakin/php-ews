<?php
/**
 * Definition of the UserConfigurationType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

use PhpEws\EWSType\EWSType;

/**
 * Definition of the UserConfigurationType type
 */
class UserConfigurationType extends EWSType
{
    /**
     * UserConfigurationName property
     *
     * @var PhpEws\EWSType\UserConfigurationNameType
     */
    public $UserConfigurationName;
    
    /**
     * ItemId property
     *
     * @var PhpEws\EWSType\ItemIdType
     */
    public $ItemId;
    
    /**
     * Dictionary property
     *
     * @var PhpEws\EWSType\UserConfigurationDictionaryType
     */
    public $Dictionary;
    
    /**
     * XmlData property
     *
     * @var string
     * @todo consider how to handle base64Binary
     */
    public $XmlData;
    
    /**
     * BinaryData property
     *
     * @var string
     * @todo consider how to handle base64Binary
     */
    public $BinaryData;

}
