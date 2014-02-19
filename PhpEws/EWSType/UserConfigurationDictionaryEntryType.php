<?php
/**
 * Definition of the UserConfigurationDictionaryEntryType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

use PhpEws\EWSType\EWSType;

/**
 * Definition of the UserConfigurationDictionaryEntryType type
 */
class UserConfigurationDictionaryEntryType extends EWSType
{
    /**
     * DictionaryKey property
     *
     * @var PhpEws\EWSType\UserConfigurationDictionaryObjectType
     */
    public $DictionaryKey;
    
    /**
     * DictionaryValue property
     *
     * @var PhpEws\EWSType\UserConfigurationDictionaryObjectType
     */
    public $DictionaryValue;
}
