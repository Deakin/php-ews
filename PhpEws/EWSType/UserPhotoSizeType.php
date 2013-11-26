<?php
/**
 * Definition of the GetUserPhotoType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

/**
 * Default get user photo
 */
class UserPhotoSizeType extends EWSType
{
    /**
     * All SizeRequested property possible values
     *
     * @var string
     */
    const HR48x48 = 'HR48x48';
    const HR64x64 = 'HR64x64';
    const HR96x96 = 'HR96x96';
    const HR120x120 = 'HR120x120';
    const HR240x240 = 'HR240x240';
    const HR360x360 = 'HR360x360';
    const HR432x432 = 'HR432x432';
    const HR504x504 = 'HR504x504';
    const HR648x648 = 'HR648x648';
    
    /**
     * @var string
     */
    public $_;

    /**
     * Returns the value of this object as a string
     *
     * @return string
     */
    public function __toString()
    {
        return $this->_;
    }
}